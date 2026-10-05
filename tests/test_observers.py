"""Observer unit tests: Beacon status classification, SSE parsing, Netdata queries."""

from __future__ import annotations

import pytest

from hermes.observer.beacon import (
    BeaconClient,
    BeaconError,
    BeaconStream,
    classify_status,
    parse_beacon_issue,
)
from hermes.observer.netdata import NetdataClient


class StubHttp:
    def __init__(self, responses: dict[str, tuple[int, object]] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[str] = []

    async def get_json(self, url, headers=None, timeout=10.0):
        self.calls.append(url)
        for key, (status, body) in self.responses.items():
            if key in url:
                return status, body
        return 404, None

    async def get_text(self, url, headers=None, timeout=10.0):
        self.calls.append(url)
        for key, (status, body) in self.responses.items():
            if key in url:
                return status, str(body)
        return 404, ""


def test_classify_status_mapping():
    assert classify_status(200, None) == "ok"
    assert classify_status(403, {"error": {"code": "DISABLED"}}) == "disabled"
    assert classify_status(403, None) == "forbidden"
    assert classify_status(401, None) == "unauthorized"
    assert classify_status(429, None) == "rate_limited"
    assert classify_status(None, None) == "unreachable"
    assert classify_status(503, None) == "server_error"


async def test_beacon_client_disabled_raises_specific_kind():
    http = StubHttp({"/api/agent/v1/summary": (403, {"error": {"code": "DISABLED", "message": "x"}})})
    client = BeaconClient(http=http, base_url="http://b", token="")
    with pytest.raises(BeaconError) as exc:
        await client.summary()
    assert exc.value.kind == "disabled"


async def test_beacon_client_sends_bearer_and_parses_envelope():
    http = StubHttp({"/api/agent/v1/docker": (200, {"data": {"containers": [{"name": "plex"}]}})})
    client = BeaconClient(http=http, base_url="http://b", token="sekret")
    containers = await client.docker()
    assert containers == [{"name": "plex"}]


async def test_beacon_client_rejects_missing_envelope():
    http = StubHttp({"/api/agent/v1/summary": (200, {"unexpected": True})})
    client = BeaconClient(http=http, base_url="http://b", token="t")
    with pytest.raises(BeaconError) as exc:
        await client.summary()
    assert exc.value.kind == "invalid_response"


def test_stream_frame_parsing():
    stream = BeaconStream(http=None, base_url="http://b", token="t")
    stream.handle_frame('event: hello\ndata: {"apiVersion":"1"}\n')
    assert stream.drain() == []
    stream.handle_frame(
        'id: 42\nevent: docker.transition\n'
        'data: {"eventId": 42, "timestamp": "2026-10-05T10:00:00Z", "name": "plex", '
        '"from": "running", "to": "exited"}\n'
    )
    events = stream.drain()
    assert len(events) == 1
    assert events[0].type == "docker.transition"
    assert events[0].data["name"] == "plex"
    assert stream.last_event_id == 42
    # heartbeat comments are ignored
    stream.handle_frame(": ping\n\n")
    assert stream.drain() == []


def test_parse_beacon_issue_normalizes():
    issue = parse_beacon_issue({
        "id": "docker:plex:unhealthy", "severity": "critical", "category": "docker",
        "status": "active", "summary": "plex unhealthy",
        "target": {"type": "container", "id": "plex", "name": "plex"},
        "metrics": {"observedForSeconds": 120}, "suggestedChecks": ["logs"],
    })
    assert issue.severity == "critical"
    assert issue.target["id"] == "plex"


async def test_netdata_chart_average_and_existence_cache():
    class NetdataHttp(StubHttp):
        async def get_json(self, url, headers=None, timeout=10.0):
            self.calls.append(url)
            if "/chart?" in url:
                if "cgroup_plex.cpu" in url:
                    return 200, {"chart": {}}
                return 404, None
            if "/data?" in url:
                return 200, {"labels": ["time", "user"], "data": [[5, 10], [4, 20], [3, 30]]}
            return 404, None

    client = NetdataClient(http=NetdataHttp(), base_url="http://n")
    value = await client.chart_average("cgroup_plex.cpu", "user", after=-60)
    assert value == 20.0
    missing = await client.chart_average("cgroup_nope.cpu", "user")
    assert missing is None
    # existence result is cached: no repeated /chart calls for the missing chart
    await client.chart_average("cgroup_nope.cpu", "user")
    assert sum(1 for c in client.http.calls if "cgroup_nope" in c and "/chart?" in c) == 1


async def test_netdata_container_health_states():
    class HealthHttp(StubHttp):
        async def get_json(self, url, headers=None, timeout=10.0):
            self.calls.append(url)
            if "/chart?" in url:
                if "unknown" in url:
                    return 404, None
                return 200, {}
            if "sonarr" in url:
                return 200, {"labels": ["time", "unhealthy", "healthy"],
                             "data": [[9, 0, 1], [8, 0, 1]]}
            if "plexdb-ro" in url:
                return 200, {"labels": ["time", "unhealthy", "healthy"],
                             "data": [[9, 1, 0], [8, 1, 0]]}
            return 404, None

    client = NetdataClient(http=HealthHttp(), base_url="http://n")
    assert await client.container_health("sonarr") == 1
    assert await client.container_health("plexdb-ro") == 0
    assert await client.container_health("unknown") is None
