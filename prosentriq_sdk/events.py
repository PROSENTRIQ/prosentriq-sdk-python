"""Builders for canonical Prosentriq events (OCSF-aligned).

Every builder returns a plain dict matching the published schema. ``uid`` is
the idempotency key: derive it deterministically from the source record when
you can (``stable_uid``) so a re-read log never double-counts."""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

NETWORK, HTTP, DNS, PROCESS, FILE, AUTH, API, FINDING = 4001, 4002, 4003, 1007, 1001, 3002, 6003, 2004
SEVERITY = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def stable_uid(*parts: Any) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:40]


def _ms(t: datetime | float | int | None) -> int:
    if t is None:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    if isinstance(t, datetime):
        return int((t if t.tzinfo else t.replace(tzinfo=timezone.utc)).timestamp() * 1000)
    return int(t * 1000) if t < 1e11 else int(t)


def base(class_uid: int, *, host_id: str, sensor_type: str = "sdk", os: str = "linux",  # noqa: A002
         time: datetime | float | None = None, uid: str | None = None, severity: str = "info",
         signal: str | None = None, signal_details: dict[str, Any] | None = None, message: str | None = None,
         activity_id: int = 0, **fields: Any) -> dict[str, Any]:
    e: dict[str, Any] = {
        "class_uid": class_uid, "activity_id": activity_id, "time": _ms(time), "severity_id": SEVERITY.get(severity, 1),
        "metadata": {"uid": uid or str(uuid.uuid4()), "product": {"name": "prosentriq-sdk", "vendor_name": "Prosentriq"}},
        "prosentriq": {"sensor_type": sensor_type, "os": os, "host_id": host_id},
    }
    if signal:
        e["prosentriq"]["signal"] = signal
        e["prosentriq"]["signal_details"] = signal_details or {}
    if message:
        e["message"] = message[:2048]
    e.update({k: v for k, v in fields.items() if v is not None})
    return e


def endpoint(ip: str | None, port: int | None = None, hostname: str | None = None) -> dict[str, Any] | None:
    if ip is None and hostname is None:
        return None
    d: dict[str, Any] = {}
    if ip:
        d["ip"] = ip
    if port is not None:
        d["port"] = int(port)
    if hostname:
        d["hostname"] = hostname
    return d


def network(src_ip: str, dst_ip: str | None = None, *, dst_port: int | None = None, src_port: int | None = None,
            bytes_out: int | None = None, bytes_in: int | None = None, process: str | None = None, **kw: Any) -> dict[str, Any]:
    traffic = {k: v for k, v in (("bytes_out", bytes_out), ("bytes_in", bytes_in)) if v is not None} or None
    return base(NETWORK, src_endpoint=endpoint(src_ip, src_port), dst_endpoint=endpoint(dst_ip, dst_port),
                traffic=traffic, process={"name": process} if process else None, **kw)


def auth(src_ip: str | None, *, user: str, success: bool, **kw: Any) -> dict[str, Any]:
    return base(AUTH, activity_id=1, status_id=1 if success else 2, src_endpoint=endpoint(src_ip),
                actor={"user": {"name": user}}, severity=kw.pop("severity", "info" if success else "low"), **kw)


def process_start(name: str, *, cmd_line: str | None = None, pid: int | None = None, user: str | None = None,
                  parent: str | None = None, container_id: str | None = None, **kw: Any) -> dict[str, Any]:
    p: dict[str, Any] = {"name": name}
    for k, v in (("cmd_line", cmd_line), ("pid", pid), ("container_id", container_id)):
        if v is not None:
            p[k] = v
    if user:
        p["user"] = {"name": user}
    if parent:
        p["parent_process"] = {"name": parent}
    return base(PROCESS, activity_id=1, process=p, **kw)


def file_activity(path: str, *, activity: str = "update", process: str | None = None, pid: int | None = None,
                  entropy: float | None = None, **kw: Any) -> dict[str, Any]:
    act = {"create": 1, "read": 2, "update": 3, "delete": 4, "rename": 5, "attributes": 6}[activity]
    f: dict[str, Any] = {"path": path}
    if entropy is not None:
        f["entropy"] = entropy
    proc = {k: v for k, v in (("name", process), ("pid", pid)) if v is not None} or None
    return base(FILE, activity_id=act, file=f, process=proc, **kw)


def dns_query(src_ip: str, hostname: str, **kw: Any) -> dict[str, Any]:
    return base(DNS, src_endpoint=endpoint(src_ip), query={"hostname": hostname}, **kw)


def cloud_api(operation: str, *, service: str, src_ip: str | None, user: str | None, provider: str = "aws",
              region: str | None = None, account: str | None = None, success: bool = True, **kw: Any) -> dict[str, Any]:
    return base(API, api={"operation": operation, "service": {"name": service}}, src_endpoint=endpoint(src_ip),
                actor={"user": {"name": user}} if user else None, status_id=1 if success else 2,
                cloud={k: v for k, v in (("provider", provider), ("region", region), ("account_uid", account)) if v}, **kw)


def finding(title: str, *, indicator: str | None = None, uid: str | None = None, **kw: Any) -> dict[str, Any]:
    return base(FINDING, finding={"title": title[:512], "uid": uid}, src_endpoint=endpoint(indicator), **kw)
