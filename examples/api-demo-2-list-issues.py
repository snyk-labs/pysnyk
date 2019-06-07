***REMOVED***

***REMOVED***
from utils import get_token

***REMOVED***
***REMOVED***
***REMOVED***'--orgId', type=str,
                        help='The Snyk Organisation Id', required=True)

***REMOVED***'--projectId', type=str,
                        help='The project ID in Snyk', required=True)

    args = parser.parse_args()

    return args

snyk_token = get_token('snyk-api-token')
***REMOVED***
***REMOVED***
project_id = args.projectId


# List issues in a project
***REMOVED***
json_res = client.snyk_projects_project_issues(org_id, project_id)
print(json_res)
for v in json_res['issues']['vulnerabilities']:
    print('\n %s' %v['title'])
    print('  %s@%s' % (v['package'], v['version']))
    print('  Severity: %s' % v['severity'])
