import pytest
from unittest.mock import Mock, patch
from FeedVulnCheckKEV import VulnCheckFeedClient, fetch_indicators, build_indicators, test_module

@pytest.fixture
def client():
    return VulnCheckFeedClient(base_url="https://api.example.com", verify=True, proxy=False, api_key="test_api_key")

def test_client_initialization():
    client = VulnCheckFeedClient(base_url="https://api.example.com", verify=True, proxy=False, api_key="test_api_key")
    assert client.base_url == "https://api.example.com"
    assert client._verify == True
    assert client._proxy == False
    assert client._headers == {
        "Authorization": "Bearer test_api_key",
        "Accept": "application/json"
    }

@patch('VulnCheckFeed.BaseClient._http_request')
def test_fetch_vulnerabilities(mock_http_request, client):
    mock_http_request.return_value = {"data": [{"cve": ["CVE-2021-1234"]}]}
    response = client.fetch_vulnerabilities(params={"limit": 10})
    assert response == {"data": [{"cve": ["CVE-2021-1234"]}]}
    mock_http_request.assert_called_once_with(
        method="GET",
        url_suffix="v3/index/vulncheck-kev",
        params={"limit": 10}
    )

def test_build_indicators():
    cves = [
        {
            "cve": ["CVE-2021-1234"],
            "_timestamp": "2021-01-01T00:00:00.000Z",
            "shortDescription": "Test description",
            "vulnerabilityName": "Test Vulnerability",
            "date_added": "2021-01-01",
            "vendorProject": "TestVendor",
            "product": "TestProduct",
            "vulncheck_xdb": [
                {
                    "xdb_url": "https://example.com/exploit",
                    "date_added": "2021-01-01T00:00:00.000",
                    "exploit_type": "PoC"
                }
            ],
            "vulncheck_reported_exploitation": [
                {
                    "url": "https://example.com/report",
                    "date_added": "2021-01-01T00:00:00.000"
                }
            ]
        }
    ]
    last_fetch_date = "2020-12-31T23:59:59.999Z"
    indicators = build_indicators(cves, last_fetch_date)
    assert len(indicators) == 1
    assert indicators[0]["value"] == "CVE-2021-1234"
    assert indicators[0]["type"] == "CVE"
    assert indicators[0]["fields"]["cvemodified"] == "2021-01-01T00:00:00.000Z"

@patch('VulnCheckFeed.VulnCheckFeedClient.fetch_vulnerabilities')
def test_fetch_indicators(mock_fetch_vulnerabilities, client):
    mock_fetch_vulnerabilities.return_value = {
        "data": [
            {
                "cve": ["CVE-2021-1234"],
                "_timestamp": "2021-01-01T00:00:00.000Z"
            }
        ],
        "_meta": {
            "page": 1,
            "total_pages": 1
        }
    }
    last_run = {"last_fetch_date": "2020-12-31T23:59:59.999Z", "is_first_run": False}
    indicators, new_last_run = fetch_indicators(client, last_run, 100)
    assert len(indicators) == 1
    assert new_last_run["last_fetch_date"] == "2021-01-01T00:00:00.000Z"
    assert new_last_run["is_first_run"] == False

@patch('VulnCheckFeed.VulnCheckFeedClient.fetch_vulnerabilities')
def test_test_module(mock_fetch_vulnerabilities, client):
    mock_fetch_vulnerabilities.return_value = {"data": []}
    result = test_module(client)
    assert result == "ok"
    mock_fetch_vulnerabilities.assert_called_once_with(params={"limit": 1})

@patch('VulnCheckFeed.VulnCheckFeedClient.fetch_vulnerabilities')
def test_test_module_failure(mock_fetch_vulnerabilities, client):
    mock_fetch_vulnerabilities.side_effect = Exception("API Error")
    with pytest.raises(Exception) as excinfo:
        test_module(client)
    assert str(excinfo.value) == "API Error"

@pytest.mark.parametrize("is_first_run,expected_date_filter", [
    (True, "pubStartDate"),
    (False, "lastModStartDate")
])
@patch('VulnCheckFeed.VulnCheckFeedClient.fetch_vulnerabilities')
def test_fetch_indicators_date_filter(mock_fetch_vulnerabilities, client, is_first_run, expected_date_filter):
    mock_fetch_vulnerabilities.return_value = {
        "data": [],
        "_meta": {
            "page": 1,
            "total_pages": 1
        }
    }
    last_run = {"last_fetch_date": "2021-01-01T00:00:00.000Z", "is_first_run": is_first_run}
    fetch_indicators(client, last_run, 100)
    call_args = mock_fetch_vulnerabilities.call_args[1]['params']
    assert expected_date_filter in call_args

@patch('VulnCheckFeed.VulnCheckFeedClient.fetch_vulnerabilities')
def test_fetch_indicators_pagination(mock_fetch_vulnerabilities, client):
    mock_fetch_vulnerabilities.side_effect = [
        {
            "data": [{"cve": ["CVE-2021-1234"], "_timestamp": "2021-01-01T00:00:00.000Z"}],
            "_meta": {"page": 1, "total_pages": 2}
        },
        {
            "data": [{"cve": ["CVE-2021-5678"], "_timestamp": "2021-01-02T00:00:00.000Z"}],
            "_meta": {"page": 2, "total_pages": 2}
        }
    ]
    last_run = {"last_fetch_date": "2020-12-31T23:59:59.999Z", "is_first_run": False}
    indicators, new_last_run = fetch_indicators(client, last_run, 100)
    assert len(indicators) == 2
    assert new_last_run["last_fetch_date"] == "2021-01-02T00:00:00.000Z"

def test_build_indicators_edge_cases():
    cves = [
        {
            "cve": [],  # Empty CVE
            "_timestamp": "2021-01-01T00:00:00.000Z",
        },
        {
            # Missing _timestamp
            "cve": ["CVE-2021-1234"],
        },
        {
            "cve": ["CVE-2021-5678"],
            "_timestamp": "2021-01-02T00:00:00.000Z",
            "cisa_date_added": "2021-01-02",  # Test CISA KEV
        }
    ]
    last_fetch_date = "2020-12-31T23:59:59.999Z"
    indicators = build_indicators(cves, last_fetch_date)
    assert len(indicators) == 2  # Should skip the one without _timestamp
    assert indicators[0]["value"] == "Unknown"
    assert indicators[1]["value"] == "CVE-2021-5678"
    assert indicators[1]["fields"]["cisakev"] == True

@patch('VulnCheckFeed.demisto.getLastRun')
@patch('VulnCheckFeed.demisto.setLastRun')
@patch('VulnCheckFeed.fetch_indicators')
def test_fetch_indicators_command(mock_fetch_indicators, mock_set_last_run, mock_get_last_run, client):
    mock_get_last_run.return_value = {"last_fetch_date": "2021-01-01T00:00:00.000Z", "is_first_run": False}
    mock_fetch_indicators.return_value = (
        [{"value": "CVE-2021-1234", "type": "CVE"}],
        {"last_fetch_date": "2021-01-02T00:00:00.000Z", "is_first_run": False}
    )
    
    from VulnCheckFeed import fetch_indicators_command
    indicators = fetch_indicators_command(client, 100)
    
    assert len(indicators) == 1
    assert indicators[0]["value"] == "CVE-2021-1234"
    mock_set_last_run.assert_called_once_with({"last_fetch_date": "2021-01-02T00:00:00.000Z", "is_first_run": False})
