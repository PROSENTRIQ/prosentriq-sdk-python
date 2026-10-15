"""Log relay sensor (blueprint 3.2 step 6, "network appliances"; and 4.3
side-by-side mode).

Listens for syslog (UDP and TCP, RFC 3164 and 5424, RFC 6587 framing) or
tails files, and turns lines into canonical events:

  * CEF (firewalls, IDS, other security tools)      -> Network Activity / Detection Finding
  * Suricata EVE JSON (alert, flow, dns, ssh)        -> Detection Finding / Network / DNS
  * OpenSSH auth lines (Failed/Accepted/Invalid user) -> Authentication (feeds the brute-force chain)

In ``--incumbent VENDOR`` mode, CEF alerts are forwarded to the side-by-side
endpoint (/v2/displacement/alerts) instead, so the platform can produce the
"what they missed, what we caught" report without scoring the incumbent.
"""
from __future__ import annotations

import json
import logging
import re
import socketserver
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from prosentriq_sdk import events as ev

log = logging.getLogger("prosentriq.logrelay")

_RFC5424 = re.compile(r"^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|\[.*?\])\s?(.*)$")
_RFC3164 = re.compile(r"^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d) (\S+) ([^:\[\s]+)(?:\[\d+\])?:\s?(.*)$")
_SSH_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)")
_SSH_OK = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (\S+) from (\S+) port (\d+)")
_SSH_INVALID = re.compile(r"Invalid user (\S+) from (\S+)(?: port (\d+))?")
CEF_SEV = {range(0, 4): "low", range(4, 7): "medium", range(7, 9): "high", range(9, 11): "critical"}


def parse_syslog(line: str) -> dict[str, Any]:
    line = line.rstrip("\r\n")
    m = _RFC5424.match(line)
    if m:
        pri, ts, host, app, _pid, _msgid, msg = m.groups()
        return {"pri": int(pri), "time": _iso(ts), "host": host if host != "-" else None, "app": app, "msg": msg}
    m = _RFC3164.match(line)
    if m:
        pri, ts, host, app, msg = m.groups()
        t = datetime.strptime(f"{datetime.now(timezone.utc).year} {ts}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        return {"pri": int(pri), "time": t, "host": host, "app": app, "msg": msg}
    return {"pri": None, "time": None, "host": None, "app": None, "msg": line}


def _iso(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_cef(msg: str) -> dict[str, Any] | None:
    i = msg.find("CEF:")
    if i < 0:
        return None
    body = msg[i + 4:]
    parts, cur, esc = [], [], False
    for ch in body:  # split the 7 header fields on unescaped pipes
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == "|" and len(parts) < 7:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    if len(parts) < 8:
        return None
    ext: dict[str, str] = {}
    for m in re.finditer(r"(\w+)=((?:\\=|[^=])*?)(?=\s+\w+=|$)", parts[7]):
        ext[m.group(1)] = m.group(2).replace("\\=", "=").replace("\\n", "\n").replace("\\\\", "\\").strip()
    try:
        sev_num = int(parts[6])
    except ValueError:
        sev_num = {"low": 3, "medium": 5, "high": 8, "very-high": 10, "critical": 10}.get(parts[6].lower(), 5)
    severity = next(v for r, v in CEF_SEV.items() if min(max(sev_num, 0), 10) in r)
    return {"vendor": parts[1], "product": parts[2], "version": parts[3], "signature": parts[4], "name": parts[5],
            "severity": severity, "ext": ext}


class Converter:
    """line -> canonical event (or incumbent alert)."""

    def __init__(self, host_id: str, incumbent: str | None = None) -> None:
        self.host_id = host_id
        self.incumbent = incumbent

    def convert(self, line: str) -> tuple[str, dict[str, Any]] | None:
        s = line.strip()
        if not s:
            return None
        if s.startswith("{"):
            return self._suricata(s)
        sl = parse_syslog(s)
        msg = sl["msg"]
        host = sl["host"] or self.host_id
        # CEF devices often omit the syslog app tag, so "CEF:" can be consumed
        # as the tag by the RFC 3164 pattern: look for it on the whole line.
        cef = parse_cef(msg) or parse_cef(s)
        if cef:
            return self._cef(cef, sl, host, s)
        if (sl["app"] or "").startswith("sshd") or "sshd" in msg[:40]:
            return self._ssh(msg, sl, host, s)
        return None

    def _uid(self, raw: str) -> str:
        return ev.stable_uid(self.host_id, raw)

    def _cef(self, c: dict[str, Any], sl: dict[str, Any], host: str, raw: str) -> tuple[str, dict[str, Any]]:
        x = c["ext"]
        src = x.get("src") or x.get("sourceAddress")
        t = sl["time"] or _ms_to_dt(x.get("rt"))
        if self.incumbent:
            return "incumbent", {"uid": x.get("externalId") or self._uid(raw), "time": (t or datetime.now(timezone.utc)).isoformat(),
                                 "indicator": src or x.get("shost"), "title": c["name"][:500], "severity": c["severity"],
                                 "raw": {"vendor": c["vendor"], "product": c["product"], "signature": c["signature"]}}
        e = ev.finding(f"{c['vendor']} {c['product']}: {c['name']}", indicator=src, uid=self._uid(raw), host_id=host,
                       sensor_type="log_relay", time=t, severity=c["severity"], message=c["name"])
        if x.get("dst"):
            e["dst_endpoint"] = ev.endpoint(x["dst"], int(x["dpt"]) if x.get("dpt", "").isdigit() else None)
        return "event", e

    def _ssh(self, msg: str, sl: dict[str, Any], host: str, raw: str) -> tuple[str, dict[str, Any]] | None:
        for rx, ok in ((_SSH_FAIL, False), (_SSH_INVALID, False), (_SSH_OK, True)):
            m = rx.search(msg)
            if m:
                user, ip = m.group(1), m.group(2)
                return "event", ev.auth(ip, user=user, success=ok, host_id=host, sensor_type="log_relay",
                                        time=sl["time"], uid=self._uid(raw), message=msg[:500])
        return None

    def _suricata(self, s: str) -> tuple[str, dict[str, Any]] | None:
        try:
            j = json.loads(s)
        except ValueError:
            return None
        et = j.get("event_type")
        t = _iso(j.get("timestamp", "")) if j.get("timestamp") else None
        src, dst = j.get("src_ip"), j.get("dest_ip")
        common = {"host_id": j.get("host") or self.host_id, "sensor_type": "log_relay", "time": t,
                  "uid": ev.stable_uid(self.host_id, j.get("flow_id"), et, j.get("timestamp"))}
        if et == "alert":
            a = j.get("alert", {})
            sev = {1: "high", 2: "medium", 3: "low"}.get(a.get("severity"), "medium")
            if self.incumbent:
                return "incumbent", {"uid": common["uid"], "time": (t or datetime.now(timezone.utc)).isoformat(),
                                     "indicator": src, "title": a.get("signature", "Suricata alert")[:500], "severity": sev}
            e = ev.finding(f"Suricata: {a.get('signature')}", indicator=src, severity=sev, **common)
            e["dst_endpoint"] = ev.endpoint(dst, j.get("dest_port"))
            e["unmapped"] = {"suricata_sid": a.get("signature_id"), "category": a.get("category")}
            return "event", e
        if et == "dns" and j.get("dns", {}).get("rrname"):
            return "event", ev.dns_query(src, j["dns"]["rrname"], **common)
        if et == "flow":
            f = j.get("flow", {})
            return "event", ev.network(src, dst, dst_port=j.get("dest_port"), src_port=j.get("src_port"),
                                       bytes_out=f.get("bytes_toserver"), bytes_in=f.get("bytes_toclient"), **common)
        return None


def _ms_to_dt(v: str | None) -> datetime | None:
    if v and v.isdigit():
        return datetime.fromtimestamp(int(v) / 1000, tz=timezone.utc)
    return None


class Batcher:
    """Collects converted records and flushes every ``interval`` s or ``size`` items."""

    def __init__(self, flush: Callable[[list[dict[str, Any]], list[dict[str, Any]]], None], interval: float = 5, size: int = 500) -> None:
        self.flush_fn = flush
        self.interval = interval
        self.size = size
        self.events: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        threading.Thread(target=self._timer, daemon=True).start()

    def add(self, kind: str, rec: dict[str, Any]) -> None:
        with self.lock:
            (self.alerts if kind == "incumbent" else self.events).append(rec)
            full = len(self.events) + len(self.alerts) >= self.size
        if full:
            self.flush()

    def flush(self) -> None:
        with self.lock:
            e, a = self.events, self.alerts
            self.events, self.alerts = [], []
        if e or a:
            try:
                self.flush_fn(e, a)
            except Exception:  # noqa: BLE001 - the SDK client spools; never kill the listener
                log.exception("flush failed")

    def _timer(self) -> None:
        while True:
            time.sleep(self.interval)
            self.flush()


def serve(conv: Converter, batcher: Batcher, host: str = "0.0.0.0", port: int = 5514) -> None:
    class UDP(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data = self.request[0].decode(errors="replace")
            for line in data.splitlines():
                r = conv.convert(line)
                if r:
                    batcher.add(*r)

    class TCP(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            buf = b""
            while True:
                chunk = self.request.recv(65536)
                if not chunk:
                    break
                buf += chunk
                frames, used = split_frames(buf)
                buf = buf[used:]
                if len(buf) > 1 << 20:
                    buf = b""  # a single frame over 1 MiB is garbage; drop it
                for line in frames:
                    r = conv.convert(line)
                    if r:
                        batcher.add(*r)

    class TS(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True
        daemon_threads = True

    udp = socketserver.ThreadingUDPServer((host, port), UDP)
    tcp = TS((host, port), TCP)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    log.info("log relay listening on %s:%d (udp+tcp)", host, port)
    tcp.serve_forever()


def split_frames(buf: bytes) -> tuple[list[str], int]:
    """RFC 6587 framing: octet-counted ('123 <pri>...') or newline-delimited.
    Returns (complete frames, bytes consumed); the caller keeps buf[consumed:]."""
    frames: list[str] = []
    i = 0
    while i < len(buf):
        m = re.match(rb"(\d+) ", buf[i:i + 12])
        if m:
            start = i + m.end()
            end = start + int(m.group(1))
            if end > len(buf):
                break
            frames.append(buf[start:end].decode(errors="replace"))
            i = end
            continue
        j = buf.find(b"\n", i)
        if j < 0:
            break
        frames.append(buf[i:j].decode(errors="replace"))
        i = j + 1
    return frames, i


def tail(path: str, conv: Converter, batcher: Batcher, from_start: bool = False) -> None:
    with open(path, errors="replace") as f:
        if not from_start:
            f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            r = conv.convert(line)
            if r:
                batcher.add(*r)

