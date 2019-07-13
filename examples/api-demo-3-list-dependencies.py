import argparse

from snyk import SnykClient
from utils import get_default_token_path, get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation Id", required=True
    )
    parser.add_argument(
        "--projectId", type=str, help="The project ID in Snyk", required=True
    )
    return parser.parse_args()


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId
project_id = args.projectId


client = SnykClient(snyk_token)
dependencies = (
    client.organizations.get(org_id).projects.get(project_id).dependencies.all()
)

for dep in dependencies:
    print("%s@%s" % (dep.name, dep.version))

    licenses = dep.licenses
    if len(licenses) > 0:
        print("  Licenses:")
        for l in licenses:
            print("   - %s | %s" % (l.license, l.id))

    deps_with_issues = dep.dependenciesWithIssues
    if len(deps_with_issues) > 0:
        print("  Deps with Issues:")
        for d in deps_with_issues:
            print("   - %s" % d)
