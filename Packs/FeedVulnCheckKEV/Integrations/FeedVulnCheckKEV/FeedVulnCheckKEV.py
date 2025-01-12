import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401


class VulnCheckFeedClient(BaseClient):
    """
    Client to interact with the VulnCheck API.
    """

    def __init__(self, base_url, verify, proxy, api_key):
        """
        Initializes the client with the base URL, headers, and settings.

        Args:
            base_url (str): The base URL of the VulnCheck API.
            verify (bool): Whether to verify SSL certificates.
            proxy (bool): Whether to use system proxy settings.
            api_key (str): API key for authentication.
        """
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json"
        }
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers)

    def fetch_vulnerabilities(self, params=None):
        """
        Fetch vulnerabilities from the API.

        Args:
            params (dict): Parameters to send with the API request.

        Returns:
            dict: API response containing vulnerability data.
        """
        return self._http_request(
            method="GET",
            url_suffix="v3/index/vulncheck-kev",
            params=params
        )


def build_indicators(cves, last_fetch_date):
    """
    Build indicators from the fetched CVEs.

    Args:
        cves (list): List of CVEs fetched from the API.
        last_fetch_date (str): The timestamp of the last fetch.

    Returns:
        list: List of indicators to be created.
    """
    indicators = []
    for vuln in cves:
        if vuln.get("_timestamp", "") > last_fetch_date:
            indicators.append({
                "value": vuln.get("cve", ["Unknown"])[0],  # Using CVE as the unique value
                "type": "CVE",
                "rawJSON": vuln,
                "fields": {
                    "cvemodified": vuln.get("_timestamp", ""),
                    "cisakev": "cisa_date_added" in vuln,
                    "exploited": True,
                    "knownransomwarecampaign": vuln.get("knownRansomwareCampaignUse") != "Unknown",
                    "description": vuln.get("shortDescription", ""),
                    "name": vuln.get("vulnerabilityName", ""),
                    "published": vuln.get("date_added", ""),
                    "tags": [vuln.get("vendorProject", ""), vuln.get("product", "")],
                    "trafficlightprotocol": "TLP:AMBER",
                    "updateddate": vuln.get("_timestamp", ""),
                    "vulncheckexploitdatabase": [
                        {
                            "url": exploit.get("xdb_url", ""),
                            "dateadded": exploit.get("date_added", "1970-01-01T00:00:00.000"),
                            "exploittype": exploit.get("exploit_type", "")
                        }
                        for exploit in vuln.get("vulncheck_xdb", [])
                    ],
                    "vulncheckreportedexploitation": [
                        {
                            "url": reports.get("url", ""),
                            "dateadded": reports.get("date_added", "1970-01-01T00:00:00.000")
                        }
                        for reports in vuln.get("vulncheck_reported_exploitation", [])
                    ]
                }
            })
    return indicators


def fetch_indicators(client: VulnCheckFeedClient, last_run, limit):
    """
    Fetch vulnerabilities from the API and build indicators.

    Args:
        client (VulnCheckFeedClient): Client instance to communicate with the API.
        last_run (dict): Last run state containing `last_fetch_date` and other metadata.
        limit (int): Maximum number of indicators to fetch.

    Returns:
        tuple: List of indicators and updated last run metadata.
    """
    last_fetch_date = last_run.get("last_fetch_date", "1970-01-01T00:00:00.000Z")
    is_first_run = last_run.get("is_first_run", True)

    # Determine the date filter for the API
    date_filter_key = "pubStartDate" if is_first_run else "lastModStartDate"
    date_filter_value = "1970-01-01" if is_first_run else last_fetch_date.split("T")[0]

    params = {
        "limit": limit,
        date_filter_key: date_filter_value
    }

    all_cves = []
    while True:
        response = client.fetch_vulnerabilities(params=params)
        cves = response.get("data", [])
        meta = response.get("_meta", {})
        all_cves.extend(cves)

        # Pagination handling
        current_page = meta.get("page", 1)
        total_pages = meta.get("total_pages", 1)
        if current_page >= total_pages:
            break
        params["page"] = current_page + 1

    # Build indicators
    indicators = build_indicators(all_cves, last_fetch_date)

    # Update last run metadata
    if all_cves:
        latest_timestamp = max(vuln["_timestamp"] for vuln in all_cves if "_timestamp" in vuln)
        last_run = {
            "last_fetch_date": latest_timestamp,
            "is_first_run": False
        }

    return indicators, last_run


def fetch_indicators_command(client: VulnCheckFeedClient, limit: int):
    """
    Command to fetch and return indicators for Cortex XSOAR.

    Args:
        client (VulnCheckFeedClient): Client instance to communicate with the API.
        limit (int): Maximum number of indicators to fetch.

    Returns:
        list: List of indicators.
    """
    last_run = demisto.getLastRun() or {}
    indicators, last_run = fetch_indicators(client, last_run, limit)
    demisto.setLastRun(last_run)
    return indicators


def test_module(client: VulnCheckFeedClient):
    """
    Test the connectivity and configuration of the integration.

    Args:
        client (VulnCheckFeedClient): The client instance for API communication.

    Returns:
        str: "ok" if the test passes.
    """
    client.fetch_vulnerabilities(params={"limit": 1})
    return "ok"


def main():
    """
    Main function for the integration.
    """
    params = demisto.params()
    base_url = params.get("url")
    api_key = params.get("api_key", {}).get("password")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    limit = int(params.get("max_fetch", 100))

    if not api_key:
        return_error("API key is required for this integration.")

    client = VulnCheckFeedClient(
        base_url=base_url,
        verify=verify,
        proxy=proxy,
        api_key=api_key
    )

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-indicators":
            indicators = fetch_indicators_command(client, limit)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
