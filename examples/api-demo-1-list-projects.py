import argparse

from pysnyk import SnykClient
from utils import get_token

def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument('--orgId', type=str,
                        help='The Snyk Organisation Id', required=True)

    args = parser.parse_args()

    return args

snyk_token = get_token('snyk-api-token')
args = parse_command_line_args()
org_id = args.orgId


# List projects in org
client = SnykClient(token=snyk_token)
json_res = client.snyk_projects_projects(org_id)
for proj in json_res['projects']:
    print('\nProject Name: %s' % proj['name'])
    print('  Issues Found:')
    print('      High  : %s' % proj['issueCountsBySeverity']['high'])
    print('      Medium: %s' % proj['issueCountsBySeverity']['medium'])
    print('      Low   : %s' % proj['issueCountsBySeverity']['low'])

