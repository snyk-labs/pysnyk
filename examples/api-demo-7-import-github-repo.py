import argparse

from snyk import SnykClient
from utils import get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation ID", required=True
    )
    parser.add_argument(
        "--githubOrg", type=str, help="The GitHub organization name", required=True
    )
    parser.add_argument(
        "--repoName", type=str, help="The GitHub repository name", required=True
    )
    parser.add_argument(
        "--githubIntegrationId",
        type=str,
        help="GitHub integration ID - get this from Settings->Integrations",
        required=True,
    )
    parser.add_argument(
        "--manifestFiles",
        nargs="*",
        help='Leave this empty to import all or make a list of paths/to/build/files (ex "build.gradle" or "someModule/pom.xml")',
        required=False,
    )
    return parser.parse_args()


snyk_token = get_token("snyk-api-token")
args = parse_command_line_args()
org_id = args.orgId
github_org = args.githubOrg
repo_name = args.repoName
github_integration_id = args.githubIntegrationId
manifest_files = args.manifestFiles

client = SnykClient(snyk_token)
http_resp = client.snyk_integrations_import(
    org_id, github_integration_id, github_org, repo_name, manifest_files
)
if http_resp.status_code == 201:
    print("Project imported or already exists")
    print("%s %s" % (http_resp.status_code, http_resp.reason))
else:
    print("Failed importing project")
    print(http_resp.status_code)
    print(http_resp.reason)
    print(http_resp)
