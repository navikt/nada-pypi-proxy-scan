import os
import subprocess
import tempfile
from slack import WebClient
from slack.errors import SlackApiError
from google.cloud import artifactregistry_v1

import logging
logging.basicConfig(level=logging.INFO)


def append_to_slack_error_reports(slack_error_reports: list, package: str, error_message: str):
    error_report = f"`{package}`:\n\n"+f"```{error_message}```"
    slack_error_reports.append(
        {
            "type": "section",
            "text": {
                "type": "mrkdwn", 
                "text": error_report,
            }
        }
    )


def scan_package_version(scan_errors: list, package: str, version: str):
    package_and_version = f"{package}=={version}"
    tmp = tempfile.NamedTemporaryFile()
    with open(tmp.name, 'w') as f:
        f.write(f"{package_and_version}")

    logging.info(f"Scanning {package_and_version}")
    result = subprocess.run(["pip-audit", "-r", tmp.name, "-l", "--cache-dir", "/tmp"], capture_output=True)
    if result.returncode != 0:
        scan_error_report = f"{result.stderr.decode('utf-8')}\n{result.stdout.decode('utf-8')}"
        logging.error(scan_error_report)
        append_to_slack_error_reports(scan_errors, package_and_version, scan_error_report)


def post_slack_message(scan_error_reports):
    try:
        slack_token = os.environ["SLACK_TOKEN"]
        slack_channel = os.environ["SLACK_CHANNEL"]
    except KeyError:
        logging.warning("Not publishing slack notification as environment variables SLACK_TOKEN and SLACK_CHANNEL are not set")
        return
    else:
        client = WebClient(token=slack_token)
        try:
            client.chat_postMessage(
                channel=slack_channel,
                text="PYPI proxy security scan errors",
                blocks=scan_error_reports,
            )
        except SlackApiError as e:
            logging.error(f"Error sending slack notification {e.response['error']}")


if __name__ == "__main__":
    try:
        gar_repo_path = os.environ["GAR_REPOSITORY_PATH"]
    except KeyError:
        raise KeyError("GAR_REPOSITORY_PATH env is not set")

    scan_errors = []
    client = artifactregistry_v1.ArtifactRegistryClient()
    request = artifactregistry_v1.ListPackagesRequest(
        parent=gar_repo_path,
    )
    packages = client.list_packages(request=request)

    for package in packages:
        request = artifactregistry_v1.ListVersionsRequest(
            parent=package.name,
        )
        versions = client.list_versions(request=request)
        for version in versions:
            scan_package_version(scan_errors, package.name.split("/")[-1], version.name.split("/")[-1])

    if len(scan_errors) > 0:
        scan_errors = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn", 
                    "text": ":warning: _*PYPI proxy vulnerability scan report*_",
                }
            }
        ] + scan_errors
        post_slack_message(scan_errors)
