import argparse

from snyk import SnykClient
from utils import get_default_token_path, get_token
import re


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("--orgId", type=str, help="The Snyk Organisation ID")

    group.add_argument(
        "--orgName", type=str, help="The Snyk Organisation Name (case insensitive)"
    )

    parser.add_argument(
        "--projectPattern",
        type=str,
        help="A RE pattern used to match on projects in an organization",
        default=".*",
    )

    parser.add_argument(
        "--criticality",
        type=str,
        help="Value for criticality",
        default=None,
        choices=["critical", "high", "medium", "low"],
    )

    parser.add_argument(
        "--environment",
        type=str,
        help="Value of the environment",
        default=None,
        choices=[
            "frontend",
            "backend",
            "internal",
            "external",
            "mobile",
            "saas",
            "onprem",
            "hosted",
            "distributed",
        ],
    )

    parser.add_argument(
        "--lifecycle",
        type=str,
        help="Value of the lifecycle",
        default=None,
        choices=["production", "development", "sandbox",],
    )

    parser.add_argument("--dry", help="Dry run", default=False, action="store_true")

    return parser.parse_args()


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId  # type: str
org_name = args.orgName  # type: str
criticality = args.criticality  # type: str
lifecycle = args.lifecycle # type: str
environment = args.environment # type: str
dry = args.dry  # type: bool

re_pattern = re.compile(args.projectPattern)

client = SnykClient(token=snyk_token)

if org_name:
    org = client.organizations.filter(name=org_name.capitalize())
    if len(org) != 1:
        raise ValueError("Did not find unique organization")
    org_id = org[0].id

for proj in client.organizations.get(org_id).projects.all():
    if not re_pattern.match(proj.name):
        continue

    print(f"\nProject name: {proj.name}")
    print(proj.attributes.set(criticality=criticality,lifecycle=lifecycle,environment=environment))
