import argparse
import os

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

client = SnykClient(token=os.getenv('PYSNYK_TOKEN'), debug=True, tries=1, delay=2, backoff=2)
for proj in client.organizations.get(org_id).projects.all():
    print("\nProject name: %s" % proj.name)
    print("  Issues Found:")
    print("      High  : %s" % proj.issueCountsBySeverity.high)
    print("      Medium: %s" % proj.issueCountsBySeverity.medium)
    print("      Low   : %s" % proj.issueCountsBySeverity.low)
