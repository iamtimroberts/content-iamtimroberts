import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from glob import glob
from zipfile import ZipFile
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend

# TODO make this dynamic
local_tag = "r2023-11-06"
local_dir = "/sigma/**/*.yml"

response = requests.get("https://api.github.com/repos/SigmaHQ/sigma/releases/latest")
latest_tag = response.json()["tag_name"]

if latest_tag != local_tag:
    latest_url = (
        "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip"
    )
    latest_zip_file = f"{local_dir}/sigma_all_rules.zip"

    with requests.get(latest_url, stream=True) as r:
        r.raise_for_status()
        with open(latest_zip_file, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    with ZipFile(latest_zip_file, "r") as zip_object:
        zip_object.extractall(local_dir)

    with open(f"{local_dir}/version.txt", encoding="us-ascii") as f:
        for line in f:
            if match := re.search("(?P<name>\d{4}-\d{1,2}-\d{1,2})", line):
                release_date = f"r{match.groups()[0]}"
                break
        local_tag = release_date

    demisto.log("new rules found")

count = 0
yml_files = glob(local_dir, recursive=True)
for file in yml_files[:9]:
    with open(file) as yml:
        # pipeline = sysmon_pipeline()
        backend = LuceneBackend()
        rule = SigmaCollection.from_yaml(yml)
        lucene = backend.convert(rule)
        rule = rule[0]
        ## TODO Cleanup fields (caps, underscores)
        ## TODO Add to Operating System & Kill Chain phases to match Att&ck
        sigma_dict = {
            "value": rule.title,
            "name": rule.title,
            "product": rule.logsource.product,
            "category": underscoreToCamelCase(rule.logsource.category),
            "service": rule.logsource.service,
            "logsource": rule.logsource.source,
            "ruleid": str(rule.id),
            "description": rule.description,
            "tags": [underscoreToCamelCase(tag.name) for tag in rule.tags],
            "lucene": lucene[0],
            "type": "SigmaRule",
            "falsepositives": [{"reason": reason} for reason in rule.falsepositives],
        }
        demisto.executeCommand("createNewIndicator", sigma_dict)
        count += 1
demisto.results(f"Created {count} indicators")
