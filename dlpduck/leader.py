"""Leader election, so exactly one replica runs the drop-folder watch loop.

Extraction and every console action (retry/purge/resolve/reprocess) are
already safe under concurrent, multi-pod access — they go through
`operation_lock()`/`Pipeline.job_lock()`, a real cross-process file lock
on the shared work volume. The one thing that is NOT safe to run from
more than one process at once is the watcher's own poll loop: its
size-stability and metadata-grace-period tracking (`Watcher._tracked`) is
in-memory, per-process state, so two independently polling watchers could
each decide a file is ready before the other's metadata-companion check
catches up, and could claim it under different notions of "ready".

`NullLeaderElection` — always leader, no coordination at all — is the
default. A standalone or single-pod deployment gets exactly today's
behavior, unchanged, with zero configuration. Set
`cluster.leader_election: kubernetes` to run more than one watch-capable
replica; only the pod holding the Lease actually polls.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
from datetime import UTC, datetime
from pathlib import Path

import httpx

from dlpduck.config import ClusterConfig, ConfigError

logger = logging.getLogger("dlpduck.leader")

_SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


class LeaderElection:
    """start()/stop() a background renewal loop; `is_leader` reflects its
    current state. Never raises out of the background loop — a failure to
    reach the API server just means "not leader right now", not a crash."""

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    @property
    def is_leader(self) -> bool:
        raise NotImplementedError


class NullLeaderElection(LeaderElection):
    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    @property
    def is_leader(self) -> bool:
        return True


def _now_microtime() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_microtime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class KubernetesLeaseElection(LeaderElection):
    """One coordination.k8s.io/v1 Lease per watcher group, updated over
    plain HTTPS with the pod's own in-cluster service account — no
    `kubernetes` client dependency, just the same `httpx` the console
    already needs for OIDC.
    """

    def __init__(self, config: ClusterConfig):
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if not host:
            raise ConfigError(
                "cluster.leader_election is 'kubernetes' but this process is not "
                "running inside a cluster (KUBERNETES_SERVICE_HOST is unset)"
            )
        token_path, ca_path, ns_path = (_SA_DIR / n for n in ("token", "ca.crt", "namespace"))
        if not token_path.is_file() or not ca_path.is_file():
            raise ConfigError(
                "cluster.leader_election is 'kubernetes' but the service account token/CA "
                f"are not mounted at {_SA_DIR} — automountServiceAccountToken must be enabled"
            )
        self._token_path = token_path
        self._base_url = f"https://{host}:{port}"
        self._verify = str(ca_path)
        self.name = config.lease_name
        self.namespace = config.lease_namespace or (
            ns_path.read_text().strip() if ns_path.is_file() else None
        )
        if not self.namespace:
            raise ConfigError(
                "cluster.lease_namespace is not set and could not be read from "
                f"{ns_path} — set it explicitly"
            )
        self.identity = config.identity or os.environ.get("POD_NAME") or os.environ.get("HOSTNAME") or socket.gethostname()
        self.lease_duration = config.lease_duration_seconds
        self.renew_interval = config.renew_interval_seconds

        self._is_leader = False
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def is_leader(self) -> bool:
        return self._is_leader

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="leader-election", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.renew_interval * 2)
        if self._is_leader:
            self._release()
        self._is_leader = False

    def _client(self) -> httpx.Client:
        token = self._token_path.read_text().strip()  # re-read: it rotates
        return httpx.Client(
            base_url=self._base_url,
            verify=self._verify,
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.renew_interval,
        )

    def _lease_path(self) -> str:
        return f"/apis/coordination.k8s.io/v1/namespaces/{self.namespace}/leases/{self.name}"

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception:
                logger.exception("leader election tick failed; standing down")
                self._is_leader = False
            self._stop_event.wait(self.renew_interval)

    def _tick(self) -> None:
        with self._client() as client:
            resp = client.get(self._lease_path())
            if resp.status_code == 404:
                self._is_leader = self._create(client)
                return
            resp.raise_for_status()
            lease = resp.json()
            spec = lease.get("spec", {})
            holder = spec.get("holderIdentity")
            renew_time = spec.get("renewTime")
            expired = renew_time is None or (
                (datetime.now(UTC) - _parse_microtime(renew_time)).total_seconds()
                > spec.get("leaseDurationSeconds", self.lease_duration)
            )
            if holder == self.identity:
                self._is_leader = self._renew(client, lease)
            elif expired:
                logger.info("lease %s/%s expired (held by %s) — attempting takeover", self.namespace, self.name, holder)
                self._is_leader = self._take_over(client, lease)
            else:
                self._is_leader = False

    def _create(self, client: httpx.Client) -> bool:
        body = {
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {"name": self.name, "namespace": self.namespace},
            "spec": {
                "holderIdentity": self.identity,
                "leaseDurationSeconds": int(self.lease_duration),
                "acquireTime": _now_microtime(),
                "renewTime": _now_microtime(),
                "leaseTransitions": 0,
            },
        }
        resp = client.post(
            f"/apis/coordination.k8s.io/v1/namespaces/{self.namespace}/leases", json=body
        )
        if resp.status_code == 409:
            return False  # someone else created it first
        resp.raise_for_status()
        logger.info("acquired lease %s/%s as %s", self.namespace, self.name, self.identity)
        return True

    def _renew(self, client: httpx.Client, lease: dict) -> bool:
        lease["spec"]["renewTime"] = _now_microtime()
        resp = client.put(self._lease_path(), json=lease)
        if resp.status_code == 409:
            logger.warning("lost lease %s/%s while renewing", self.namespace, self.name)
            return False
        resp.raise_for_status()
        return True

    def _take_over(self, client: httpx.Client, lease: dict) -> bool:
        lease["spec"]["holderIdentity"] = self.identity
        lease["spec"]["renewTime"] = _now_microtime()
        lease["spec"]["acquireTime"] = _now_microtime()
        lease["spec"]["leaseTransitions"] = lease["spec"].get("leaseTransitions", 0) + 1
        resp = client.put(self._lease_path(), json=lease)
        if resp.status_code == 409:
            return False  # someone else won the race
        resp.raise_for_status()
        logger.info("acquired lease %s/%s as %s (takeover)", self.namespace, self.name, self.identity)
        return True

    def _release(self) -> None:
        # Best-effort: clearing holderIdentity lets the next candidate take
        # over immediately on a clean shutdown, rather than waiting out the
        # full lease duration. A crash skips this — that's exactly what the
        # duration/expiry check is for.
        try:
            with self._client() as client:
                resp = client.get(self._lease_path())
                if resp.status_code != 200:
                    return
                lease = resp.json()
                if lease.get("spec", {}).get("holderIdentity") != self.identity:
                    return
                lease["spec"]["holderIdentity"] = None
                lease["spec"]["renewTime"] = _now_microtime()
                client.put(self._lease_path(), json=lease)
                logger.info("released lease %s/%s", self.namespace, self.name)
        except Exception:
            logger.exception("could not release lease %s/%s cleanly", self.namespace, self.name)


def build_leader_election(config: ClusterConfig) -> LeaderElection:
    if config.leader_election == "none":
        return NullLeaderElection()
    return KubernetesLeaseElection(config)
