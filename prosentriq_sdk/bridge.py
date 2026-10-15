"""The Linux sensor bridge: the engine's link to the control plane.

Runs as root next to the engine (systemd unit prosentriq-bridge). Each cycle:

  1. Heartbeat -> receive the effective autonomy level, the local circuit-
     breaker limits, the desired mode and pending directives.
  2. Write AUTONOMY_LEVEL / LOCAL_BREAKER_* / MODE into the engine's state
     file (the engine's AutonomyGate re-reads it), and reload the XDP probe
     when the desired mode changes (restart_mode: systemd | exit | none).
  3. Apply directives through the engine's authenticated local API
     (block/unblock with TTL), or directly for host-level actions (process
     freeze/thaw by signal, host isolation with nftables), then acknowledge.
  4. Ship new ThreatHistorian findings as canonical v2 events (with
     Kubernetes pod attribution when running in a DaemonSet).
  5. Fetch the signed immunity feed, verify it against the key pinned at
     enrollment, and merge it into the engine's threat-intel feed. When the
     platform changes signing key, re-pin only along its endorsement chain
     (each new key signed by the one already pinned).
  6. Watch decoy files (honeytokens) and report every access.

Every step fails independently: a down control plane never stops local
detection or enforcement; events spool to disk and replay later.
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.util
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import sqlite3
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from prosentriq_sdk import events as ev
from prosentriq_sdk.client import ApiError, Client, key_id_for, resolve_chain, verify_feed

log = logging.getLogger("prosentriq.bridge")

DEFAULTS: dict[str, Any] = {
    "engine_api": "http://127.0.0.1:18080",
    "dashboard_token_file": "/etc/prosentriq/dashboard.token",
    "state_file": "/etc/prosentriq/prosentriq.state",
    "historian_db": "/etc/prosentriq/config/threat_history.db",
    "cursor_file": "/var/lib/prosentriq/bridge.cursor",
    "spool_dir": "/var/lib/prosentriq/spool",
    "immunity_file": "/etc/prosentriq/config/immunity_feed.txt",
    # The platform signing key this host trusts, once it has moved past the
    # one pinned at enrollment (written only after an endorsement verified).
    "pinned_key_file": "/var/lib/prosentriq/signing_key.json",
    "threat_intel_list": "/etc/prosentriq/config/live_threat_intel.txt",
    # The engine's private Redis: a root-only Unix socket (prosentriq-redis
    # unit). {"unix_socket": ""} plus host/port selects TCP (development).
    "redis": {"unix_socket": "/run/prosentriq-redis/redis.sock"},
    "nft": "/usr/sbin/nft",
    "management_cidrs": [],
    # DNS servers an isolated host may still query. Empty: the host's own
    # resolvers (resolv.conf, or systemd-resolved's upstream servers).
    "isolation_dns_servers": [],
    "decoy_files": [],
    "kubernetes": False,
}

# Engine event types that are local decisions or high-volume telemetry, not
# findings. Decisions are made (and ledgered) centrally; shipping these would
# double-count.
SKIP_TYPES = {"GENERIC_PACKET", "NETWORK_WARN", "THREAT_NEUTRALIZED", "AUTO_BLOCK_CRITICAL", "AUTO_BLOCK_HIGH",
              "AUTO_BLOCK_MEDIUM", "WOULD_BLOCK", "MANUAL_BLOCK", "MANUAL_WHITELIST"}
FIM_CONTEXT = [("Creation", "FIM_CREATE"), ("Deletion", "FIM_DELETE"), ("Overwrite", "FIM_MOVE"), ("Move", "FIM_MOVE"),
               ("Permissions", "FIM_ATTRIB"), ("Payload Write", "FIM_CLOSE_WRITE"), ("Modification", "FIM_MODIFY")]
_NUM = r"([0-9]+(?:\.[0-9]+)?)"


def parse_details(event_type: str, details: str) -> tuple[str, dict[str, Any]]:
    """Turn the engine's human-readable ThreatHistorian details back into the
    structured fields the platform's reason sentences use."""
    d: dict[str, Any] = {"raw": details[:1000]} if details else {}

    def grab(pattern: str, key: str, cast=str) -> None:
        m = re.search(pattern, details or "")
        if m:
            try:
                d[key] = cast(m.group(1))
            except ValueError:
                pass

    if event_type == "FIM_VIOLATION":
        path, _, ctx = (details or "").partition(" - ")
        d["path"] = path.strip()
        code = next((c for word, c in FIM_CONTEXT if word.lower() in ctx.lower()), "FIM_MODIFY")
        return code, d
    grab(r"[Ee]ntropy:? " + _NUM, "entropy", float)
    grab(r"port (\d+)", "port", int)
    grab(r"Contacted (\d+) unique ports", "unique_ports", int)
    grab(r"Country: (.+)$", "country")
    grab(r"JA3 Hash: (\S+)", "ja3")
    grab(r"Raw score: " + _NUM, "anomaly_score", float)
    grab(r"Process '([^']+)'", "process")
    grab(r"destination (\S+)", "dst")
    grab(r"pid=(\d+)", "pid", int)
    grab(r"cgroup=(\d+)", "cgroup", int)
    if event_type in ("DNS_SUSPICIOUS_TLD",):
        d["query"] = details
    if event_type == "DNS_HIGH_ENTROPY_DGA":
        grab(r"(\S+\.\S+)", "query")
    return event_type, d


class EngineApi:
    """The engine's local API, authenticated with the per-install token (T1)."""

    def __init__(self, base: str, token_file: str) -> None:
        self.base = base.rstrip("/")
        self.token_file = token_file

    def _token(self) -> str:
        return Path(self.token_file).read_text().strip()

    def post(self, path: str, body: dict[str, Any]) -> tuple[int, str]:
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {self._token()}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")
        except (urllib.error.URLError, OSError) as e:
            return 0, str(e)


# ---------------------------------------------------------------- state file
def read_state(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for line in Path(path).read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return out


_SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.:/@+-]*$")


def write_state(path: str, updates: dict[str, str]) -> bool:
    """Atomic update preserving unrelated keys. Values are restricted to a
    safe charset because prosentriq-ctl sources this file as shell."""
    cur = read_state(path)
    changed = False
    for k, v in updates.items():
        v = str(v)
        if not _SAFE_VALUE.match(v) or not re.match(r"^[A-Z_]+$", k):
            raise ValueError(f"refusing to write unsafe state value {k}={v!r}")
        if cur.get(k) != v:
            cur[k] = v
            changed = True
    if not changed:
        return False
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        f.write("".join(f"{k}={v}\n" for k, v in cur.items()))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return True


# ---------------------------------------------------------------- host-level actions
def freeze(pid: int, cont: bool = False) -> None:
    if pid <= 1 or pid == os.getpid():
        raise ValueError("refusing to signal pid %d" % pid)
    os.kill(pid, signal.SIGCONT if cont else signal.SIGSTOP)


RESOLV_CONF = "/etc/resolv.conf"
# systemd-resolved: /etc/resolv.conf names its loopback stub, this file the
# upstream servers the stub forwards to.
RESOLVED_UPSTREAM = "/run/systemd/resolve/resolv.conf"


def _nameservers(path: str) -> list[str]:
    out: list[str] = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    try:
                        out.append(str(ipaddress.ip_address(parts[1].split("%", 1)[0])))
                    except ValueError:
                        continue
    except OSError:
        pass
    return out


def system_resolvers(resolv_conf: str = RESOLV_CONF, upstream: str = RESOLVED_UPSTREAM) -> list[str] | None:
    """The DNS servers this host actually sends queries to, or None when they
    cannot be determined (a local caching resolver whose upstreams are unknown)."""
    servers = _nameservers(resolv_conf)
    remote = [s for s in servers if not ipaddress.ip_address(s).is_loopback]
    if servers and len(remote) == len(servers):
        return remote
    found = remote + [s for s in _nameservers(upstream) if not ipaddress.ip_address(s).is_loopback]
    return list(dict.fromkeys(found)) or None


def isolation_ruleset(allow_cidrs: list[str], api_host_ips: list[str], dns_servers: list[str] | None = None) -> str:
    """nftables ruleset restricting the host to the management plane (blueprint
    4.8 #5). Loopback, established flows, DNS and the control plane stay up.

    DNS goes only to ``dns_servers`` (the host's resolvers): open port 53 to
    the whole internet would leave an isolated host a DNS-tunnelling channel
    to its attacker. ``None`` (resolvers unknown) keeps any destination, so
    the host can still find the control plane that releases it."""
    v4, v6 = [], []
    for c in list(allow_cidrs) + api_host_ips:
        net = ipaddress.ip_network(c, strict=False)
        (v4 if net.version == 4 else v6).append(str(net))
    dns4 = [d for d in dns_servers or [] if ipaddress.ip_address(d).version == 4]
    dns6 = [d for d in dns_servers or [] if ipaddress.ip_address(d).version == 6]
    lines = ["table inet prosentriq_isolation {", "  chain input { type filter hook input priority -10; policy drop;",
             "    iif lo accept", "    ct state established,related accept"]
    if v4:
        lines.append(f"    ip saddr {{ {', '.join(v4)} }} accept")
    if v6:
        lines.append(f"    ip6 saddr {{ {', '.join(v6)} }} accept")
    lines += ["  }", "  chain output { type filter hook output priority -10; policy drop;",
              "    oif lo accept", "    ct state established,related accept"]
    if dns_servers is None:
        lines += ["    udp dport 53 accept", "    tcp dport 53 accept"]
    else:
        for fam, servers in (("ip", dns4), ("ip6", dns6)):
            if servers:
                lines += [f"    {fam} daddr {{ {', '.join(servers)} }} {proto} dport 53 accept" for proto in ("udp", "tcp")]
    if v4:
        lines.append(f"    ip daddr {{ {', '.join(v4)} }} accept")
    if v6:
        lines.append(f"    ip6 daddr {{ {', '.join(v6)} }} accept")
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- decoy files (honeytokens) via inotify
class DecoyWatcher(threading.Thread):
    IN_ACCESS, IN_OPEN = 0x00000001, 0x00000020

    def __init__(self, paths: list[str], on_access) -> None:
        super().__init__(daemon=True, name="decoy-watch")
        self.paths = [p for p in paths if os.path.exists(p)]
        self.on_access = on_access
        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        self.libc = ctypes.CDLL(libc_name, use_errno=True)

    def run(self) -> None:
        if not self.paths:
            return
        fd = self.libc.inotify_init1(os.O_CLOEXEC)
        if fd < 0:
            log.error("inotify_init1 failed: errno %d", ctypes.get_errno())
            return
        wds = {}
        for p in self.paths:
            wd = self.libc.inotify_add_watch(fd, p.encode(), self.IN_ACCESS | self.IN_OPEN)
            if wd >= 0:
                wds[wd] = p
        last: dict[str, float] = {}
        while True:
            buf = os.read(fd, 4096)
            i = 0
            while i + 16 <= len(buf):
                wd, mask, _cookie, ln = struct.unpack_from("iIII", buf, i)
                i += 16 + ln
                p = wds.get(wd)
                if p and time.time() - last.get(p, 0) > 30:  # one report per 30 s per file
                    last[p] = time.time()
                    self.on_access(p)


# ---------------------------------------------------------------- the bridge
class Bridge:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = {**DEFAULTS, **cfg}
        self.client = Client(self.cfg["api_base"], self.cfg["token"], spool_dir=self.cfg["spool_dir"])
        self.engine = EngineApi(self.cfg["engine_api"], self.cfg["dashboard_token_file"])
        self.host_id = self.cfg.get("host_id") or socket.gethostname()
        self.acks: list[dict[str, Any]] = []
        self.timed_blocks: dict[str, float] = {}
        self.feed_at: str | None = None
        self.pinned_key, self.pinned_key_id = load_pinned_key(self.cfg)
        self._unresolved_key: str | None = None
        self.k8s = None
        if self.cfg["kubernetes"]:
            from prosentriq_sdk.k8s import PodResolver

            self.k8s = PodResolver()
        self._decoy_events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    # -------------------------------------------------------- 1+2 heartbeat & local policy
    def heartbeat(self) -> dict[str, Any]:
        st = read_state(self.cfg["state_file"])
        with self._lock:
            acks, self.acks = self.acks, []
        try:
            hb = self.client.heartbeat(mode="enforce" if st.get("MODE") == "production" else "observe",
                                       can_enforce=True, version=self.cfg.get("version", ""), ip=self.cfg.get("ip"),
                                       stats={"timed_blocks": len(self.timed_blocks)}, acks=acks)
        except ApiError:
            with self._lock:
                self.acks = acks + self.acks  # keep them for the next heartbeat
            raise
        updates = {"CONTROL_PLANE": "v2", "AUTONOMY_LEVEL": str(int(hb["autonomy_level"])),
                   "LOCAL_BREAKER_MAX_PER_MIN": str(int(hb["local_breaker"]["max_blocks_per_minute"])),
                   "LOCAL_BREAKER_COOLDOWN_MIN": str(int(hb["local_breaker"]["cooldown_minutes"]))}
        # Shown on the host dashboard (engine /api/autonomy). Older control
        # planes don't send these; the dashboard then shows the level alone.
        if "autonomy_configured" in hb:
            updates["AUTONOMY_CONFIGURED"] = str(int(hb["autonomy_configured"]))
        if "autonomy_held_by" in hb:
            codes = [c for c in hb.get("autonomy_held_by") or [] if re.match(r"^[a-z_]+$", str(c))]
            updates["AUTONOMY_HELD_BY"] = "+".join(codes) or "none"
        updates["AUTONOMY_SYNCED_AT"] = str(int(time.time()))
        write_state(self.cfg["state_file"], updates)
        want_prod = hb.get("desired_mode") == "enforce"
        if want_prod != (st.get("MODE") == "production"):
            self._switch_mode(want_prod)
        return hb

    def _switch_mode(self, enforce: bool) -> None:
        """Apply the control plane's desired mode. The platform has already
        checked the plan's enforcement entitlement before asking for it. The
        loader picks the XDP object from MODE (trial -> observe-only probe), so
        a probe reload is a restart of the loader and the engine."""
        mode = "production" if enforce else "trial"
        write_state(self.cfg["state_file"], {"MODE": mode})
        log.warning("desired mode is now %s; reloading the XDP probe", mode)
        audit = Path(self.cfg.get("audit_log", "/var/log/prosentriq/enforcement_audit.log"))
        try:
            audit.parent.mkdir(parents=True, exist_ok=True)
            with audit.open("a") as f:
                f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} MODE_{mode.upper()} via control plane sensor={self.cfg['sensor_id']}\n")
        except OSError:
            pass
        restart = self.cfg.get("restart_mode") or ("exit" if self.k8s is not None else "systemd")
        if restart == "none":
            return
        if restart == "exit":
            os._exit(3)  # container: the pod restarts and the loader attaches the new probe
        for unit in ("prosentriq-loader.service", "prosentriq-ai.service"):
            r = subprocess.run(["/usr/bin/systemctl", "restart", unit], capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                log.error("restart %s failed: %s", unit, r.stderr[-300:])

    # -------------------------------------------------------- 3 directives
    def apply(self, d: dict[str, Any]) -> tuple[bool, str | None]:
        kind, target = d["kind"], d["target"]
        try:
            if kind == "block_ip":
                body: dict[str, Any] = {"ip": target}
                if d.get("ttl_seconds"):
                    body["ttl_seconds"] = int(d["ttl_seconds"])
                code, txt = self.engine.post("/api/block_ip", body)
                return code == 200, None if code == 200 else f"engine {code}: {txt[:200]}"
            if kind == "unblock_ip":
                code, txt = self.engine.post("/api/unblock_ip", {"ip": target})
                return code == 200, None if code == 200 else f"engine {code}: {txt[:200]}"
            if kind in ("freeze_process", "thaw_process"):
                freeze(int(d["params"]["pid"]), cont=kind == "thaw_process")
                return True, None
            if kind == "isolate_host":
                api_host = re.sub(r"^https?://([^/:]+).*", r"\1", self.cfg["api_base"])
                api_ips = sorted({ai[4][0] for ai in socket.getaddrinfo(api_host, 443)})
                dns = [str(ipaddress.ip_address(x)) for x in self.cfg.get("isolation_dns_servers") or []] or system_resolvers()
                if dns is None:
                    log.warning("isolation: this host's DNS servers are unknown (local caching resolver); "
                                "DNS stays open to any server. Set isolation_dns_servers to close it.")
                rules = isolation_ruleset(self.cfg["management_cidrs"] + d["params"].get("allow_cidrs", []), api_ips, dns)
                r = subprocess.run([self.cfg["nft"], "-f", "-"], input=rules, capture_output=True, text=True, timeout=30)
                return r.returncode == 0, None if r.returncode == 0 else r.stderr[-300:]
            if kind == "release_host":
                r = subprocess.run([self.cfg["nft"], "delete", "table", "inet", "prosentriq_isolation"],
                                   capture_output=True, text=True, timeout=30)
                ok = r.returncode == 0 or "No such file" in r.stderr
                return ok, None if ok else r.stderr[-300:]
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
            return False, f"{type(e).__name__}: {e}"
        return False, f"unsupported directive {kind}"

    def handle_directives(self, directives: list[dict[str, Any]]) -> None:
        for d in directives:
            ok, err = self.apply(d)
            log.info("directive %s %s %s -> %s", d["id"], d["kind"], d["target"], "applied" if ok else err)
            with self._lock:
                self.acks.append({"id": d["id"], "ok": ok, "error": err})

    # -------------------------------------------------------- 4 findings
    def _cursor(self) -> int:
        try:
            return int(Path(self.cfg["cursor_file"]).read_text().strip() or 0)
        except (FileNotFoundError, ValueError):
            return 0

    def _save_cursor(self, v: int) -> None:
        p = Path(self.cfg["cursor_file"])
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(str(v))
        os.replace(tmp, p)

    def collect_findings(self, limit: int = 5000) -> tuple[list[dict[str, Any]], int]:
        db = self.cfg["historian_db"]
        if not os.path.exists(db):
            return [], self._cursor()
        cur = self._cursor()
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
        try:
            rows = con.execute("SELECT id, timestamp, ip, event_type, details FROM event_history WHERE id > ? ORDER BY id LIMIT ?",
                               (cur, limit)).fetchall()
        finally:
            con.close()
        out = []
        last = cur
        for rid, ts, ip, etype, details in rows:
            last = rid
            if etype in SKIP_TYPES:
                continue
            signal_code, d = parse_details(etype, details or "")
            extra: dict[str, Any] = {}
            if self.k8s and d.get("cgroup"):
                pod = self.k8s.lookup(int(d["cgroup"]))
                if pod:
                    extra["k8s"] = pod
            e = ev.base(4001, host_id=self.host_id, sensor_type="kubernetes" if self.k8s else "linux_engine",
                        time=float(ts), uid=ev.stable_uid(self.cfg["sensor_id"], rid), severity="medium",
                        signal=signal_code, signal_details=d, src_endpoint=ev.endpoint(_valid_ip(ip)),
                        message=f"{etype}: {details}"[:2048] if details else etype)
            if extra:
                e["prosentriq"].update(extra)
            out.append(e)
        return out, last

    def ship(self) -> dict[str, int]:
        batch, last = self.collect_findings()
        with self._lock:
            decoys, self._decoy_events = self._decoy_events, []
        totals = self.client.send(batch + decoys) if (batch or decoys) else {"accepted": 0}
        if last:
            self._save_cursor(last)  # spooled batches are durable, so the cursor can move on
        return totals

    def on_decoy_access(self, path: str) -> None:
        e = ev.file_activity(path, activity="read", host_id=self.host_id, sensor_type="linux_engine", severity="high",
                             uid=ev.stable_uid(self.cfg["sensor_id"], path, int(time.time() // 30)))
        with self._lock:
            self._decoy_events.append(e)

    # -------------------------------------------------------- 5 immunity feed
    def refresh_signing_key(self, hb: dict[str, Any]) -> bool:
        """Follow the platform to a new signing key, only if the key pinned
        here endorsed it (directly or through a chain). Returns True on re-pin."""
        current = hb.get("signing_key_id")
        if not current or not self.pinned_key or current == self.pinned_key_id or current == self._unresolved_key:
            return False
        info = self.client.signing_key()
        raw = resolve_chain({self.pinned_key_id: base64.b64decode(self.pinned_key)}, info.get("endorsements"), current)
        if raw is None:
            self._unresolved_key = current   # log once per key, not every heartbeat
            log.error("platform signs with %s, which the pinned key %s has not endorsed; immunity feeds are ignored "
                      "until an endorsement is published or this host is re-enrolled", current, self.pinned_key_id)
            return False
        try:
            save_pinned_key(self.cfg["pinned_key_file"], raw)
        except OSError as e:   # e.g. a read-only filesystem: trust it for this run, re-walk the chain after a restart
            log.error("could not save the re-pinned key to %s: %s", self.cfg["pinned_key_file"], e)
        log.warning("signing key re-pinned: %s -> %s (endorsed)", self.pinned_key_id, current)
        self.pinned_key, self.pinned_key_id = base64.b64encode(raw).decode(), current
        self.feed_at = None
        return True

    def refresh_immunity(self, hb: dict[str, Any]) -> int:
        meta = hb.get("immunity_feed")
        if not meta or meta.get("generated_at") == self.feed_at:
            return 0
        feed = self.client.immunity_feed()
        pinned = self.pinned_key
        if not pinned or not verify_feed(feed, pinned):
            log.error("immunity feed failed signature/freshness verification; ignored")
            return 0
        ips = [i["ip"] for i in feed["payload"]["indicators"]]
        p = Path(self.cfg["immunity_file"])
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text("".join(f"{ip}\n" for ip in ips))
        os.replace(tmp, p)
        self.feed_at = meta["generated_at"]
        self._publish_intel(ips)
        log.info("immunity feed verified (%s): %d indicators", feed["key_id"], len(ips))
        return len(ips)

    def _publish_intel(self, immunity_ips: list[str]) -> None:
        """Merge into the engine's threat-intel key (same union the updater does)."""
        try:
            base = [line.strip() for line in Path(self.cfg["threat_intel_list"]).read_text().splitlines() if line.strip()]
        except FileNotFoundError:
            base = []
        payload = "\n".join(dict.fromkeys(base + immunity_ips))
        resp_set("prosentriq:intel:blocklist", payload, self.cfg["redis"])

    # -------------------------------------------------------- loop
    def run(self) -> None:
        if self.cfg["decoy_files"]:
            DecoyWatcher(self.cfg["decoy_files"], self.on_decoy_access).start()
        interval = 30
        while True:
            t0 = time.time()
            try:
                hb = self.heartbeat()
                interval = int(hb.get("heartbeat_seconds", 30))
                self.handle_directives(hb.get("directives", []))
                self.refresh_signing_key(hb)
                self.refresh_immunity(hb)
            except ApiError as e:
                log.warning("control plane unavailable (%s); local protection continues", e)
            except Exception:  # noqa: BLE001 - never let one bad cycle kill the bridge
                log.exception("heartbeat cycle failed")
            try:
                self.ship()
            except Exception:  # noqa: BLE001
                log.exception("shipping findings failed")
            time.sleep(max(1.0, interval - (time.time() - t0)))


def _redis_socket(redis_cfg: dict[str, Any]) -> socket.socket:
    """Connect to the engine's Redis as configured (same rules as the engine's
    prosentriq_ipc.py): its Unix socket unless "unix_socket" is set to ""."""
    path = redis_cfg.get("unix_socket", DEFAULTS["redis"]["unix_socket"])
    if path:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect(path)
        except OSError:
            s.close()
            raise
        return s
    return socket.create_connection((redis_cfg.get("host") or "127.0.0.1", int(redis_cfg.get("port") or 6379)), timeout=5)


def resp_set(key: str, value: str, redis_cfg: dict[str, Any]) -> None:
    """Minimal Redis SET over RESP (keeps the SDK dependency-free)."""
    parts = [b"SET", key.encode(), value.encode()]
    msg = b"*%d\r\n" % len(parts) + b"".join(b"$%d\r\n%s\r\n" % (len(p), p) for p in parts)
    with _redis_socket(redis_cfg) as s:
        s.sendall(msg)
        reply = s.recv(64)
    if not reply.startswith(b"+OK"):
        raise RuntimeError(f"redis SET failed: {reply!r}")


def _valid_ip(ip: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(ip)) if ip else None
    except ValueError:
        return None


def load_pinned_key(cfg: dict[str, Any]) -> tuple[str | None, str | None]:
    """(base64 key, key id) this host trusts: a re-pinned key if one was
    saved, else the key pinned at enrollment."""
    path = cfg.get("pinned_key_file") or DEFAULTS["pinned_key_file"]
    try:
        saved = json.loads(Path(path).read_text())
        raw = base64.b64decode(saved["public_key"], validate=True)
        if len(raw) == 32 and key_id_for(raw) == saved.get("key_id"):
            return saved["public_key"], saved["key_id"]
        log.error("%s is malformed; using the key pinned at enrollment", path)
    except FileNotFoundError:
        pass
    except (ValueError, KeyError, TypeError, OSError):
        log.error("%s is unreadable; using the key pinned at enrollment", path)
    pinned = cfg.get("signing_public_key")
    if not pinned:
        return None, None
    try:
        return pinned, key_id_for(base64.b64decode(pinned, validate=True))
    except ValueError:
        return None, None


def save_pinned_key(path: str, raw: bytes) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"key_id": key_id_for(raw), "public_key": base64.b64encode(raw).decode()}, f)
    os.replace(tmp, p)


def load_config(path: str) -> dict[str, Any]:
    st = os.stat(path)
    if st.st_mode & 0o077:
        raise PermissionError(f"{path} must not be readable by group/others (chmod 600): it holds the sensor credential")
    return json.loads(Path(path).read_text())
