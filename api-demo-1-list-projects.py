import json
import argparse

import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument('--orgId', type=str,
                        help='The Snyk Organisation Id')

    args = parser.parse_args()

    if args.orgId is None:
        parser.error('You must specify --orgId')

    return args


args = parse_command_line_args()
org_id = args.orgId


# List projects in org
json_res = SnykAPI.snyk_projects_projects(org_id)
for proj in json_res['projects']:
    print('\nProject Name: %s' % proj['name'])
    print('  Issues Found:')
    print('      High  : %s' % proj['issueCountsBySeverity']['high'])
    print('      Medium: %s' % proj['issueCountsBySeverity']['medium'])
    print('      Low   : %s' % proj['issueCountsBySeverity']['low'])

