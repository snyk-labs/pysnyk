import argparse

from snyk import SnykClient
from utils import get_default_token_path, get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation ID", required=True
    )
    return parser.parse_args()


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId

show_dependencies = True
show_projects = True


client = SnykClient(snyk_token)
licenses = client.organizations.get(org_id).licenses.all()
print("\n\nNumber of licenses: %s" % len(licenses))
for license in licenses:
    print("\nLicense: %s" % (license.id))
    print("Severity: %s" % (license.severity))

    if show_dependencies:
        print("  Dependencies:")
        for dep in license.dependencies:
            print("   - %s: %s" % (dep.packageManager, dep.id))

    if show_projects:
        print("  Projects:")
        for proj in license.projects:
            print("   - %s" % proj.name)
