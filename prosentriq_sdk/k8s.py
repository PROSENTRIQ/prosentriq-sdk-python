"""Kubernetes attribution for the DaemonSet sensor (blueprint 3.2 step 2).

The engine's profiler now emits the task's cgroup v2 id (the inode number of
its cgroup directory). On a node, pod cgroups live under kubepods slices whose
paths embed the pod UID and the container id, e.g.

  /sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/
      kubepods-burstable-pod1b2c..._.slice/cri-containerd-<64 hex>.scope

``PodResolver`` maps cgroup id -> pod UID/container id by walking that tree,
then pod UID -> namespace/name/image with one list call to the API server
(pods on this node only, using the DaemonSet's service account).
"""
from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.request
from typing import Any

SA = "/var/run/secrets/kubernetes.io/serviceaccount"
_POD_RE = re.compile(r"pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})")
_CTR_RE = re.compile(r"(?:cri-containerd-|docker-|crio-)?([0-9a-f]{64})")


class PodResolver:
    def __init__(self, cgroup_root: str = "/sys/fs/cgroup", node_name: str | None = None, ttl: int = 60) -> None:
        self.root = cgroup_root
        self.node = node_name or os.environ.get("NODE_NAME", "")
        self.ttl = ttl
        self._cg: dict[int, tuple[str, str | None]] = {}
        self._pods: dict[str, dict[str, Any]] = {}
        self._at = 0.0

    def _scan_cgroups(self) -> None:
        out: dict[int, tuple[str, str | None]] = {}
        for dirpath, _dirs, _files in os.walk(self.root):
            if "kubepods" not in dirpath:
                continue
            m = _POD_RE.search(dirpath)
            if not m:
                continue
            ctr = _CTR_RE.search(os.path.basename(dirpath))
            try:
                out[os.stat(dirpath).st_ino] = (m.group(1).replace("_", "-"), ctr.group(1) if ctr else None)
            except OSError:
                continue
        self._cg = out

    def _list_pods(self) -> None:
        host, port = os.environ.get("KUBERNETES_SERVICE_HOST"), os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if not host or not os.path.exists(f"{SA}/token"):
            return
        url = f"https://{host}:{port}/api/v1/pods?fieldSelector=spec.nodeName%3D{self.node}" if self.node \
            else f"https://{host}:{port}/api/v1/pods"
        ctx = ssl.create_default_context(cafile=f"{SA}/ca.crt")
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + open(f"{SA}/token").read().strip()})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            items = json.loads(r.read())["items"]
        pods = {}
        for p in items:
            md, spec = p["metadata"], p.get("spec", {})
            pods[md["uid"]] = {"namespace": md.get("namespace"), "pod": md.get("name"),
                               "image": (spec.get("containers") or [{}])[0].get("image")}
        self._pods = pods

    def refresh(self) -> None:
        self._scan_cgroups()
        try:
            self._list_pods()
        except Exception:  # noqa: BLE001 - attribution is best-effort; detection never depends on it
            pass
        self._at = time.time()

    def lookup(self, cgroup_id: int) -> dict[str, Any] | None:
        if time.time() - self._at > self.ttl or cgroup_id not in self._cg:
            self.refresh()
        hit = self._cg.get(cgroup_id)
        if not hit:
            return None
        uid, _ctr = hit
        pod = self._pods.get(uid)
        return {k: v for k, v in (pod or {"pod": f"uid:{uid}"}).items() if v}
