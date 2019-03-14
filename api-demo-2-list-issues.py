import json
import argparse

import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument('--orgId', type=str,
                        help='The Snyk Organisation Id')

    parser.add_argument('--projectId', type=str,
                        help='The project ID in Snyk')

    args = parser.parse_args()

    if args.orgId is None:
        parser.error('You must specify --orgId')

    if args.projectId is None:
        parser.error('You must specify --projectId')

    return args


# TODO: specify --orgId=<your-org-id> as a command line parameter or just manually set it here in the code
# TODO: specify --projectId=<your-org-id> as a command line parameter or just manually set it here in the code
args = parse_command_line_args()
org_id = args.orgId
project_id = args.projectId


# List issues in a project
json_res = SnykAPI.snyk_projects_project_issues(org_id, project_id)
print(json_res)
for v in json_res['issues']['vulnerabilities']:
    print('\n %s' %v['title'])
    print('  %s@%s' % (v['package'], v['version']))
    print('  Severity: %s' % v['severity'])
