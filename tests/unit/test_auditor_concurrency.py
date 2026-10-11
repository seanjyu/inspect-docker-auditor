import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from mitmproxy.test import tflow

from inspect_docker_auditor.config import AuditorConfig
from inspect_docker_auditor.proxy_auditor import ProxyAuditor


@pytest.fixture
def auditor():
    """Fixture to instantiate ProxyAuditor with mocked config."""
    with (
        patch("os.getenv", return_value="/dummy/path"),
        patch.object(AuditorConfig, "from_yaml") as mock_cfg,
    ):
        cfg = mock_cfg.return_value
        cfg.network_rules = []
        cfg.socket_proxy_name = "localhost"
        cfg.socket_proxy_port = 2375
        cfg.cache_ttl = 60
        cfg.save_mitmproxy_logs = False
        cfg.on_violation = "block"

        yield ProxyAuditor()


@pytest.mark.unit
def test_concurrent_request_handling(auditor):
    """
    Verify that 5 simultaneous requests with 0.5s latency complete in ~0.5s (parallel),
    rather than 2.5s (sequential).
    """
    delay = 0.5
    num_requests = 5

    def mock_slow_dns(host):
        time.sleep(delay)  # Simulate slow DNS lookup inside _is_internal_host
        return "93.184.216.34"

    # Patch DNS lookup instead of the removed Docker API method
    with patch("socket.gethostbyname", side_effect=mock_slow_dns):
        flows = []
        for i in range(num_requests):
            flow = tflow.tflow(req=tflow.treq(host=f"example{i}.com"))
            flow.client_conn.peername = (f"10.0.0.{i + 1}", 12345)
            flows.append(flow)

        start_time = time.time()

        # Simulate mitmproxy calling auditor.request() concurrently across threads
        with ThreadPoolExecutor(max_workers=num_requests) as executor:
            futures = [executor.submit(auditor.request, flow) for flow in flows]
            for future in futures:
                future.result()

        elapsed_time = time.time() - start_time

        # Parallel should complete in ~0.5s instead of sequential 2.5s
        assert elapsed_time < (delay * 2), (
            f"Expected parallel execution (~{delay}s), but took {elapsed_time:.2f}s. "
            "Requests are running sequentially!"
        )
