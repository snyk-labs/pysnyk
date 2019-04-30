***REMOVED***

import SnykAPI


***REMOVED***
***REMOVED***
***REMOVED***'--orgId', type=str,
                        help='The Snyk Organisation Id')

***REMOVED***'--projectId', type=str,
                        help='The project ID in Snyk')

    args = parser.parse_args()

    if args.orgId is None:
        parser.error('You must specify --orgId')

    if args.projectId is None:
        parser.error('You must specify --projectId')

    return args


***REMOVED***
***REMOVED***
project_id = args.projectId

# Get issues in a project
json_res_project_issues = SnykAPI.snyk_projects_project_issues(org_id, project_id)

# Get issues with Jira tickets in a project
json_res_project_jira_issues = SnykAPI.snyk_projects_project_jira_issues_list_all_jira_issues(org_id, project_id)

all_vulnerability_issues = json_res_project_issues['issues']['vulnerabilities']
all_license_issues = json_res_project_issues['issues']['licenses']

all_issue_ids = []
all_issue_ids.extend([i['id'] for i in all_vulnerability_issues])
all_issue_ids.extend([i['id'] for i in all_license_issues])

issue_ids_with_jira_tickets = list(json_res_project_jira_issues.keys())

for issue in all_vulnerability_issues + all_license_issues:
    issue_id = issue['id']
    url = '  https://app.snyk.io/org/%s/project/%s#%s' % (org_id, project_id, issue_id)
    if issue_id not in issue_ids_with_jira_tickets:
        print('Found issue without Jira ticket: %s' % issue_id)
        print(url)
        package_path = ' > '.join(issue['from'])
        print('  %s\n' % package_path)
