"""Agentless cloud collector (blueprint 3.2 step 3), AWS first.

Inputs: local files or directories (plain or .gz), or an S3 prefix (needs
``pip install prosentriq-sdk[aws]``). Formats:

  * VPC Flow Logs (default v2 format, or any custom format with a header
    line) -> Network Activity. Rejected flows are also aggregated per source:
    one source touching >= 15 distinct ports is reported as PORT_SCAN_DETECTED,
    the same signal and threshold the host engine uses.
  * CloudTrail (``{"Records": [...]}``) -> API Activity; ConsoleLogin becomes
    Authentication so the platform's brute-force -> success chain applies to
    cloud consoles too.

Records get deterministic uids, so re-reading a file never double-counts.
GCP and Azure collectors follow the same shape (roadmap).
"""
from __future__ import annotations

import gzip
import ipaddress
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from prosentriq_sdk import events as ev

DEFAULT_FLOW_FIELDS = ["version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
                       "packets", "bytes", "start", "end", "action", "log-status"]
SCAN_PORT_THRESHOLD = 15  # engine parity: ReputationEngine PORT_SCAN_THRESHOLD


def _open(path: Path) -> Iterator[str]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", errors="replace") as f:  # type: ignore[operator]
        yield from f


def _ip(v: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(v)))
    except ValueError:
        return None


def flow_events(lines: Iterator[str], host_id: str, source: str) -> Iterator[dict[str, Any]]:
    fields = DEFAULT_FLOW_FIELDS
    rejects: dict[str, set[int]] = defaultdict(set)
    first_seen: dict[str, float] = {}
    for n, line in enumerate(lines):
        parts = line.split()
        if not parts:
            continue
        if n == 0 and parts[0] == "version":
            fields = parts
            continue
        rec = dict(zip(fields, parts))
        src, dst = _ip(rec.get("srcaddr")), _ip(rec.get("dstaddr"))
        if not src or rec.get("log-status") in ("NODATA", "SKIPDATA"):
            continue
        start = float(rec["start"]) if rec.get("start", "-").isdigit() else datetime.now(timezone.utc).timestamp()
        dport = int(rec["dstport"]) if rec.get("dstport", "-").isdigit() else None
        e = ev.network(src, dst, dst_port=dport, src_port=int(rec["srcport"]) if rec.get("srcport", "-").isdigit() else None,
                       bytes_out=int(rec["bytes"]) if rec.get("bytes", "-").isdigit() else None,
                       host_id=host_id, sensor_type="cloud_collector", os="aws", time=start,
                       uid=ev.stable_uid(source, n), unmapped={"action": rec.get("action"), "interface": rec.get("interface-id")})
        e["cloud"] = {"provider": "aws", "account_uid": rec.get("account-id")}
        yield e
        if rec.get("action") == "REJECT" and dport is not None:
            rejects[src].add(dport)
            first_seen.setdefault(src, start)
    for src, ports in rejects.items():
        if len(ports) >= SCAN_PORT_THRESHOLD:
            yield ev.network(src, None, host_id=host_id, sensor_type="cloud_collector", os="aws", time=first_seen[src],
                             uid=ev.stable_uid(source, "scan", src), signal="PORT_SCAN_DETECTED",
                             signal_details={"unique_ports": len(ports), "source": "vpc_flow_logs"}, severity="medium")


def cloudtrail_events(doc: dict[str, Any], host_id: str) -> Iterator[dict[str, Any]]:
    for r in doc.get("Records", []):
        ident = r.get("userIdentity") or {}
        user = ident.get("arn") or ident.get("userName") or ident.get("type")
        src = _ip(r.get("sourceIPAddress"))
        t = datetime.fromisoformat(r["eventTime"].replace("Z", "+00:00")) if r.get("eventTime") else None
        uid = r.get("eventID") or ev.stable_uid(json.dumps(r, sort_keys=True))
        failed = bool(r.get("errorCode"))
        if r.get("eventName") == "ConsoleLogin":
            outcome = (r.get("responseElements") or {}).get("ConsoleLogin")
            yield ev.auth(src, user=user or "unknown", success=outcome == "Success", host_id=host_id,
                          sensor_type="cloud_collector", os="aws", time=t, uid=uid,
                          cloud={"provider": "aws", "region": r.get("awsRegion"), "account_uid": r.get("recipientAccountId")})
            continue
        yield ev.cloud_api(r.get("eventName", "?"), service=r.get("eventSource", "?"), src_ip=src, user=user,
                           region=r.get("awsRegion"), account=r.get("recipientAccountId"), success=not failed,
                           host_id=host_id, sensor_type="cloud_collector", os="aws", time=t, uid=uid,
                           severity="low" if failed else "info",
                           unmapped={"errorCode": r.get("errorCode"), "userAgent": (r.get("userAgent") or "")[:200]})


def from_path(path: str, kind: str, host_id: str) -> Iterator[dict[str, Any]]:
    p = Path(path)
    files = sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p]
    for f in files:
        if kind == "vpc-flow":
            yield from flow_events(_open(f), host_id, str(f))
        else:
            text = "".join(_open(f))
            yield from cloudtrail_events(json.loads(text), host_id)


def from_s3(bucket: str, prefix: str, kind: str, host_id: str, state_file: str) -> Iterator[dict[str, Any]]:
    """Process objects newer than the last one recorded in ``state_file``."""
    import boto3  # optional dependency

    s3 = boto3.client("s3")
    last = Path(state_file).read_text().strip() if os.path.exists(state_file) else ""
    paginator = s3.get_paginator("list_objects_v2")
    newest = last
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix, StartAfter=last or prefix):
        for obj in page.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            if obj["Key"].endswith(".gz"):
                body = gzip.decompress(body)
            text = body.decode(errors="replace")
            if kind == "vpc-flow":
                yield from flow_events(iter(text.splitlines()), host_id, f"s3://{bucket}/{obj['Key']}")
            else:
                yield from cloudtrail_events(json.loads(text), host_id)
            newest = max(newest, obj["Key"])
            Path(state_file).write_text(newest)
