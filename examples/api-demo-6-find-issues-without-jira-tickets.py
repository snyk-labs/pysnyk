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

# Get issues in a project
client = SnykClient(token=snyk_token)
json_res_project_issues = client.snyk_projects_project_issues(
    org_id, project_id)

# Get issues with Jira tickets in a project
json_res_project_jira_issues = client.snyk_projects_project_jira_issues_list_all_jira_issues(
    org_id, project_id)

all_vulnerability_issues = json_res_project_issues['issues']['vulnerabilities']
all_license_issues = json_res_project_issues['issues']['licenses']

all_issue_ids = []
all_issue_ids.extend([i['id'] for i in all_vulnerability_issues])
all_issue_ids.extend([i['id'] for i in all_license_issues])

issue_ids_with_jira_tickets = list(json_res_project_jira_issues.keys())

for issue in all_vulnerability_issues + all_license_issues:
    issue_id = issue['id']
    url = '  https://app.snyk.io/org/%s/project/%s#%s' % (
        org_id, project_id, issue_id)
    if issue_id not in issue_ids_with_jira_tickets:
        print('Found issue without Jira ticket: %s' % issue_id)
        print(url)
        package_path = ' > '.join(issue['from'])
        print('  %s\n' % package_path)
