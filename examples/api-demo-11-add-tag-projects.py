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

    parser.add_argument("--tagName", type=str, help="Name of the tag", required=True)

    parser.add_argument("--tagValue", type=str, help="Value of the tag", required=True)

    parser.add_argument("--dry", help="Dry run", default=False, action="store_true")

    return parser.parse_args()


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId  # type: str
org_name = args.orgName  # type: str
tag_name = args.tagName  # type: str
tag_value = args.tagValue  # type: str
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

    tags = proj.tags.all()
    if not tags:
        print("\nNo tags")
    else:
        print(f"\nCurrent tags: ")
        for tag in tags:
            print(f"\t - {tag.get('key')}: {tag.get('value')}")

    if not dry:
        print(f"Adding tag: {tag_name}: {tag_value}")
        proj.tags.add(tag_name, tag_value)
    else:
        print(f"Not adding tag {tag_name}: {tag_value} (Dry run)")
