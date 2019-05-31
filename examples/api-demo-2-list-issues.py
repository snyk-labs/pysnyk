import argparse

from snyk import SnykClient
from utils import get_token

def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument('--orgId', type=str,
                        help='The Snyk Organisation Id', required=True)

    parser.add_argument('--projectId', type=str,
                        help='The project ID in Snyk', required=True)

    args = parser.parse_args()

    return args

snyk_token = get_token('snyk-api-token')
args = parse_command_line_args()
org_id = args.orgId
project_id = args.projectId


# List issues in a project
client = SnykClient(token=snyk_token)
json_res = client.snyk_projects_project_issues(org_id, project_id)
print(json_res)
for v in json_res['issues']['vulnerabilities']:
    print('\n %s' %v['title'])
    print('  %s@%s' % (v['package'], v['version']))
    print('  Severity: %s' % v['severity'])
