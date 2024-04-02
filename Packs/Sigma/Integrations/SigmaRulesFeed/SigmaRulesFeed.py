import demistomock as demisto  # noqa: F401
import urllib3
from glob import glob
from zipfile import ZipFile
#from sigma.collection import SigmaCollection
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()

LATEST_TAG_URL = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"
LATEST_RULES_URL = (
    "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip"
)
LOCAL_DIR = "/sigma"


class Client(BaseClient):
    """_summary_

    Args:
        BaseClient (_type_): _description_
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        res = self._http_request("GET", full_url=LATEST_TAG_URL, resp_type="json")
        self.latest_tag = res["tag_name"]

    def download_rules(self):
        """_summary_"""

        latest_zip_file = f"{LOCAL_DIR}/sigma_all_rules.zip"

        with self._http_request(
            "GET", full_url=LATEST_RULES_URL, resp_type="resp", stream=True
        ) as r:
            r.raise_for_status()
            with open(latest_zip_file, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)

        with ZipFile(latest_zip_file, "r") as zip_object:
            zip_object.extractall(LOCAL_DIR)

    def build_iterator(self, backend: str) -> list:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """
        self.download_rules()

        if backend == "elastic":
            from sigma.backends.elasticsearch import LuceneBackend

            self.backend = LuceneBackend()
        elif backend == "splunk":
            from sigma.backends.splunk import SplunkBackend

            self.backend = SplunkBackend()
        elif backend == "cortex":
            from sigma.backends.cortexxdr import CortexXDRBackend

            self.backend = CortexXDRBackend()

        set_integration_context({"last_fetch_tag": self.latest_tag})
        yml_files = glob(f"{LOCAL_DIR}/**/*.yml", recursive=True)
        return yml_files
        """
        result = []

        # In this case the feed output is in text format, so extracting the indicators from the response requires
        # iterating over it's lines solely. Other feeds could be in other kinds of formats (CSV, MISP, etc.), or might
        # require additional processing as well.
        try:
            indicators = res.split("\n")

            for indicator in indicators:
                # Infer the type of the indicator using 'auto_detect_indicator_type(indicator)' function
                # (defined in CommonServerPython).
                if auto_detect_indicator_type(indicator):
                    result.append(
                        {
                            "value": indicator,
                            "type": auto_detect_indicator_type(indicator),
                            "FeedURL": self._base_url,
                        }
                    )

        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(
                f"Could not parse returned data as indicator. \n\nError massage: {err}"
            )
        return result
        """


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """
    last_fetch_tag = get_integration_context().get("last_fetch_tag")
    if client.latest_tag != last_fetch_tag:
        res = client.build_iterator(backend="elastic")
        print(res[1])
        return "ok"
    else:
        return "new files"

def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()

    # Get the service API url
    base_url = params.get("url")

    # If your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    insecure = not params.get("insecure", False)

    # If your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get("proxy", False)

    command = demisto.command()
    args = demisto.args()

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            verify=insecure,
            proxy=proxy,
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == "helloworld-get-indicators":
            # This is the command that fetches a limited number of indicators from the feed source
            # and displays them in the war room.
            return_results(get_indicators_command(client, params, args))

        elif command == "fetch-indicators":
            # This is the command that initiates a request to the feed endpoint and create new indicators objects from
            # the data fetched. If the integration instance is configured to fetch indicators, then this is the command
            # that will be executed at the specified feed fetch interval.
            indicators = fetch_indicators_command(client, params)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()

register_module_line('SigmaRulesFeed', 'end', __line__())
