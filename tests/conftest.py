import pytest

from tests.mock_cortex import server as mock_server


@pytest.fixture
def cortex():
    """A running mock Cortex. Yields (mock, base_url)."""
    httpd, mock, url = mock_server.start(api_keys={"test-key": "SOC", "acme-key": "ACME"})
    yield mock, url
    httpd.shutdown()
