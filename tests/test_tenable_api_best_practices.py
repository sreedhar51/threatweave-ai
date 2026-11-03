"""Mocked compatibility tests sourced from the official Tenable integration guides.

No production credentials or network requests are used.
"""
import json
import httpx
from threatweave.tenable import TenableExportClient
from threatweave.securitycenter import SecurityCenterClient


def test_vm_standard_user_agent_and_documented_asset_chunk_size():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={'export_uuid': 'demo-job'})

    client = TenableExportClient('fake-access', 'fake-secret', transport=httpx.MockTransport(handler))
    try:
        assert client.start_export('asset') == 'demo-job'
        assert requests[0].url.path == '/assets/v2/export'
        assert json.loads(requests[0].content) == {'chunk_size': 4000}
        assert requests[0].headers['User-Agent'].startswith('Integration/1.0 (')
        assert 'ThreatWeave AI' in requests[0].headers['User-Agent']
    finally:
        client.close()


def test_vm_failed_export_fails_closed():
    def handler(request):
        if request.method == 'POST':
            return httpx.Response(200, json={'export_uuid': 'demo-job'})
        return httpx.Response(200, json={'status': 'FAILED', 'chunks_available': []})

    client = TenableExportClient('fake', 'fake', transport=httpx.MockTransport(handler))
    try:
        import pytest
        with pytest.raises(RuntimeError, match='FAILED'):
            list(client.fetch_export('vulnerability', poll_seconds=0))
    finally:
        client.close()


def test_sc_default_filter_excludes_was_and_standard_identification():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={'error_code': 0, 'response': {'results': []}})

    client = SecurityCenterClient('https://sc.example.invalid', 'fake-access', 'fake-secret', transport=httpx.MockTransport(handler))
    try:
        assert list(client.iter_analysis()) == []
        request = requests[0]
        assert request.url.path == '/rest/analysis'
        assert request.headers['User-Agent'].startswith('Integration/1.0 (')
        filters = json.loads(request.content)['query']['filters']
        assert any(f['filterName'] == 'wasVuln' and f['value'] == 'excludeWas' for f in filters)
        assert any(f['filterName'] == 'severity' and f['value'] == '1,2,3,4' for f in filters)
    finally:
        client.close()


def test_sc_429_retries_serially(monkeypatch):
    requests = []
    sleeps = []
    monkeypatch.setattr('threatweave.securitycenter.time.sleep', sleeps.append)

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(429, headers={'Retry-After': '0'})
        return httpx.Response(200, json={'error_code': 0, 'response': {'results': []}})

    client = SecurityCenterClient('https://sc.example.invalid', 'a', 'b', transport=httpx.MockTransport(handler))
    try:
        assert list(client.iter_analysis()) == []
        assert len(requests) == 2 and sleeps == [0]
    finally:
        client.close()
