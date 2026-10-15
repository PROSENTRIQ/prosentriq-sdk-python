"""``prosentriq-sensor`` command line.

    prosentriq-sensor enroll --api-base URL [--enroll-key KEY | --enroll-key-file F] [--type linux_engine] [--out /etc/prosentriq/bridge.json]
        (or the key in PROSENTRIQ_ENROLL_KEY: a command line is readable by every local user)
    prosentriq-sensor bridge --config /etc/prosentriq/bridge.json
    prosentriq-sensor relay  --config FILE [--listen 0.0.0.0:5514] [--tail /var/log/auth.log ...] [--incumbent VENDOR]
    prosentriq-sensor cloud  --config FILE --kind vpc-flow|cloudtrail (--path P | --s3 bucket/prefix [--state F]) [--loop 300]
    prosentriq-sensor verify-feed --config FILE
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import socket
import sys
import threading
import time
from pathlib import Path


def _write_config(path: str, cfg: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, p)


def _primary_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # no packet is sent for UDP connect
            return s.getsockname()[0]
    except OSError:
        return None


def _enroll_key(args: argparse.Namespace) -> str:
    if args.enroll_key_file:
        f = sys.stdin if args.enroll_key_file == "-" else open(args.enroll_key_file)
        with f:
            return f.readline().strip()
    return (args.enroll_key or os.environ.get("PROSENTRIQ_ENROLL_KEY") or "").strip()


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    ap = argparse.ArgumentParser(prog="prosentriq-sensor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll")
    e.add_argument("--api-base", required=True)
    keys = e.add_mutually_exclusive_group()
    keys.add_argument("--enroll-key", help="visible in the process list; prefer --enroll-key-file or PROSENTRIQ_ENROLL_KEY")
    keys.add_argument("--enroll-key-file", help="read the enrollment key from this file ('-' for stdin)")
    e.add_argument("--type", default="linux_engine",
                   choices=["linux_engine", "kubernetes", "log_relay", "cloud_collector", "sdk"])
    e.add_argument("--hostname", default=socket.gethostname())
    e.add_argument("--can-enforce", action="store_true")
    e.add_argument("--out", default="/etc/prosentriq/bridge.json")
    e.add_argument("--label", action="append", default=[], help="key=value")
    b = sub.add_parser("bridge")
    b.add_argument("--config", default="/etc/prosentriq/bridge.json")
    r = sub.add_parser("relay")
    r.add_argument("--config", required=True)
    r.add_argument("--listen", default="0.0.0.0:5514")
    r.add_argument("--tail", action="append", default=[])
    r.add_argument("--incumbent", help="forward CEF/Suricata alerts as this vendor's alerts (side-by-side mode)")
    c = sub.add_parser("cloud")
    c.add_argument("--config", required=True)
    c.add_argument("--kind", required=True, choices=["vpc-flow", "cloudtrail"])
    c.add_argument("--path")
    c.add_argument("--s3", help="bucket/prefix")
    c.add_argument("--state", default="/var/lib/prosentriq/cloud.state")
    c.add_argument("--loop", type=int, default=0, help="re-scan every N seconds (S3 mode)")
    v = sub.add_parser("verify-feed")
    v.add_argument("--config", required=True)
    args = ap.parse_args(argv)

    from prosentriq_sdk.client import Client, verify_feed

    if args.cmd == "enroll":
        key = _enroll_key(args)
        if not key:
            ap.error("enroll needs --enroll-key-file, PROSENTRIQ_ENROLL_KEY or --enroll-key")
        labels = dict(x.split("=", 1) for x in args.label)
        resp = Client.enroll(args.api_base, key, hostname=args.hostname, sensor_type=args.type,
                             os=platform.system().lower(), arch=platform.machine(), version="2.0.0",
                             can_enforce=args.can_enforce, ip=_primary_ip(), labels=labels)
        cfg = {"api_base": resp["api_base"] if resp["api_base"].startswith("https://") else args.api_base,
               "sensor_id": resp["sensor_id"], "token": resp["token"], "tenant_id": resp["tenant_id"],
               "signing_public_key": resp["signing_key"]["public_key"], "signing_key_id": resp["signing_key"]["key_id"],
               "host_id": args.hostname, "ip": _primary_ip(), "kubernetes": args.type == "kubernetes"}
        _write_config(args.out, cfg)
        print(f"enrolled sensor {resp['sensor_id']}; credentials written to {args.out} (0600)")
        return 0

    from prosentriq_sdk.bridge import load_config

    cfg = load_config(args.config)
    client = Client(cfg["api_base"], cfg["token"], spool_dir=cfg.get("spool_dir", "/var/lib/prosentriq/spool"))
    if args.cmd == "bridge":
        from prosentriq_sdk.bridge import Bridge

        Bridge(cfg).run()
    elif args.cmd == "relay":
        from prosentriq_sdk.sensors import logrelay

        conv = logrelay.Converter(cfg.get("host_id", socket.gethostname()), incumbent=args.incumbent)
        alerts_key = cfg.get("ingest_api_key")  # incumbent alerts go through an API key with the ingest scope

        def flush(events: list, alerts: list) -> None:
            if events:
                client.send(events)
            if alerts:
                if not alerts_key:
                    raise RuntimeError("side-by-side mode needs ingest_api_key in the config")
                Client(cfg["api_base"], alerts_key)._call("POST", "/v2/displacement/alerts",
                                                         {"vendor": args.incumbent, "alerts": alerts})

        batcher = logrelay.Batcher(flush)
        for path in args.tail:
            threading.Thread(target=logrelay.tail, args=(path, conv, batcher), daemon=True).start()
        host, port = args.listen.rsplit(":", 1)
        logrelay.serve(conv, batcher, host, int(port))
    elif args.cmd == "cloud":
        from prosentriq_sdk.sensors import cloud

        while True:
            if args.path:
                totals = client.send(cloud.from_path(args.path, args.kind, cfg.get("host_id", "aws")))
            else:
                bucket, _, prefix = args.s3.partition("/")
                totals = client.send(cloud.from_s3(bucket, prefix, args.kind, cfg.get("host_id", "aws"), args.state))
            print(json.dumps(totals))
            if not args.loop:
                break
            time.sleep(args.loop)
    elif args.cmd == "verify-feed":
        from prosentriq_sdk.bridge import load_pinned_key

        feed = client.immunity_feed()
        ok = verify_feed(feed, load_pinned_key(cfg)[0] or "")
        print(f"{'VALID' if ok else 'INVALID'} feed {feed['key_id']}: {len(feed['payload']['indicators'])} indicators")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
