"""Leader election: the default must be a no-op (standalone/single-pod
deployments never touch a Kubernetes API), and the Lease-backed election
must correctly create, renew, and take over an expired lease without a
real cluster — verified against a fake API server (httpx.MockTransport)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from dlpduck import leader as leader_module
from dlpduck.config import ClusterConfig, ConfigError
from dlpduck.leader import (
    KubernetesLeaseElection,
    NullLeaderElection,
    _now_microtime,
    build_leader_election,
)


class TestNullLeaderElection:
    def test_always_leader_and_start_stop_are_no_ops(self):
        election = NullLeaderElection()
        assert election.is_leader
        election.start()
        assert election.is_leader
        election.stop()
        assert election.is_leader

    def test_build_leader_election_returns_null_by_default(self):
        assert isinstance(build_leader_election(ClusterConfig()), NullLeaderElection)


@pytest.fixture
def sa_dir(tmp_path, monkeypatch):
    directory = tmp_path / "serviceaccount"
    directory.mkdir()
    (directory / "token").write_text("test-token")
    (directory / "ca.crt").write_text("test-ca")
    (directory / "namespace").write_text("dlpduck")
    monkeypatch.setattr(leader_module, "_SA_DIR", directory)
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")
    return directory


def _lease_body(*, holder, renew_time, transitions=0):
    return {
        "apiVersion": "coordination.k8s.io/v1",
        "kind": "Lease",
        "metadata": {"name": "dlpduck-watcher", "namespace": "dlpduck"},
        "spec": {
            "holderIdentity": holder,
            "leaseDurationSeconds": 15,
            "acquireTime": renew_time,
            "renewTime": renew_time,
            "leaseTransitions": transitions,
        },
    }


class _FakeApi:
    """A minimal in-memory stand-in for the Lease sub-resource of the k8s
    API server: GET 404s until a lease exists, POST creates it (409 if it
    already does), PUT replaces it (409 if the caller doesn't hold it and
    the lease isn't expired, mimicking optimistic concurrency closely
    enough for these tests)."""

    def __init__(self, initial: dict | None = None):
        self.lease = initial
        self.requests: list[tuple[str, str]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, str(request.url)))
        if request.method == "GET":
            if self.lease is None:
                return httpx.Response(404, json={"reason": "NotFound"})
            return httpx.Response(200, json=self.lease)
        if request.method == "POST":
            if self.lease is not None:
                return httpx.Response(409, json={"reason": "AlreadyExists"})
            self.lease = json.loads(request.content)
            return httpx.Response(201, json=self.lease)
        if request.method == "PUT":
            self.lease = json.loads(request.content)
            return httpx.Response(200, json=self.lease)
        raise AssertionError(f"unexpected method {request.method}")


def _wire(election: KubernetesLeaseElection, api: _FakeApi, monkeypatch) -> None:
    def fake_client():
        return httpx.Client(base_url="https://testserver", transport=httpx.MockTransport(api.handler))

    monkeypatch.setattr(election, "_client", fake_client)


class TestKubernetesLeaseElectionConfigValidation:
    def test_refuses_outside_a_cluster(self, tmp_path):
        with pytest.raises(ConfigError, match="not running inside a cluster"):
            KubernetesLeaseElection(ClusterConfig(leader_election="kubernetes"))

    def test_refuses_without_a_mounted_service_account(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
        monkeypatch.setattr(leader_module, "_SA_DIR", tmp_path / "nowhere")
        with pytest.raises(ConfigError, match="service account token"):
            KubernetesLeaseElection(ClusterConfig(leader_election="kubernetes"))

    def test_build_leader_election_selects_kubernetes(self, sa_dir):
        election = build_leader_election(ClusterConfig(leader_election="kubernetes"))
        assert isinstance(election, KubernetesLeaseElection)
        assert election.namespace == "dlpduck"


class TestKubernetesLeaseElectionTick:
    def _election(self, sa_dir, **overrides):
        overrides.setdefault("identity", "pod-a")
        return KubernetesLeaseElection(ClusterConfig(leader_election="kubernetes", **overrides))

    def test_creates_the_lease_when_none_exists_and_becomes_leader(self, sa_dir, monkeypatch):
        election = self._election(sa_dir)
        api = _FakeApi(initial=None)
        _wire(election, api, monkeypatch)

        election._tick()

        assert election.is_leader
        assert api.lease["spec"]["holderIdentity"] == "pod-a"

    def test_a_second_replica_does_not_win_the_create_race(self, sa_dir, monkeypatch):
        election = self._election(sa_dir, identity="pod-b")
        api = _FakeApi(initial=_lease_body(holder="pod-a", renew_time=_now_microtime()))
        _wire(election, api, monkeypatch)

        election._tick()

        assert not election.is_leader
        assert api.lease["spec"]["holderIdentity"] == "pod-a"

    def test_the_current_holder_renews_and_stays_leader(self, sa_dir, monkeypatch):
        election = self._election(sa_dir)
        original_renew = _now_microtime()
        api = _FakeApi(initial=_lease_body(holder="pod-a", renew_time=original_renew))
        _wire(election, api, monkeypatch)

        election._tick()

        assert election.is_leader
        assert api.lease["spec"]["holderIdentity"] == "pod-a"
        assert api.lease["spec"]["renewTime"] != original_renew

    def test_a_live_lease_held_by_someone_else_is_left_alone(self, sa_dir, monkeypatch):
        election = self._election(sa_dir, identity="pod-b")
        api = _FakeApi(initial=_lease_body(holder="pod-a", renew_time=_now_microtime()))
        _wire(election, api, monkeypatch)

        election._tick()

        assert not election.is_leader
        assert api.lease["spec"]["holderIdentity"] == "pod-a"

    def test_an_expired_lease_is_taken_over(self, sa_dir, monkeypatch):
        election = self._election(sa_dir, identity="pod-b", lease_duration_seconds=15)
        stale = (datetime.now(UTC) - timedelta(seconds=60)).isoformat(timespec="microseconds").replace("+00:00", "Z")
        api = _FakeApi(initial=_lease_body(holder="pod-a", renew_time=stale))
        _wire(election, api, monkeypatch)

        election._tick()

        assert election.is_leader
        assert api.lease["spec"]["holderIdentity"] == "pod-b"
        assert api.lease["spec"]["leaseTransitions"] == 1

    def test_losing_a_takeover_race_leaves_the_challenger_not_leader(self, sa_dir, monkeypatch):
        election = self._election(sa_dir, identity="pod-b")
        stale = (datetime.now(UTC) - timedelta(seconds=60)).isoformat(timespec="microseconds").replace("+00:00", "Z")
        api = _FakeApi(initial=_lease_body(holder="pod-a", renew_time=stale))

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "PUT":
                return httpx.Response(409, json={"reason": "Conflict"})
            return api.handler(request)

        monkeypatch.setattr(
            election, "_client",
            lambda: httpx.Client(base_url="https://testserver", transport=httpx.MockTransport(handler)),
        )

        election._tick()

        assert not election.is_leader

    def test_stop_releases_the_lease_when_currently_leader(self, sa_dir, monkeypatch):
        election = self._election(sa_dir)
        api = _FakeApi(initial=None)
        _wire(election, api, monkeypatch)
        election._tick()
        assert election.is_leader

        election.stop()

        assert api.lease["spec"]["holderIdentity"] is None
        assert not election.is_leader

    def test_an_api_error_leaves_the_election_not_leader_rather_than_raising(self, sa_dir, monkeypatch):
        election = self._election(sa_dir)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"reason": "InternalError"})

        monkeypatch.setattr(
            election, "_client",
            lambda: httpx.Client(base_url="https://testserver", transport=httpx.MockTransport(handler)),
        )

        # _run() (the background thread body) must swallow this, not crash.
        election._stop_event.set()  # so _run exits after one tick
        election._run()

        assert not election.is_leader
