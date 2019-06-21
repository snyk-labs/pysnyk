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
lst_licenses = client.snyk_dependencies_list_all_dependencies_by_project(org_id, project_id,1,0)

for v in lst_licenses:
    print('\n%s: %s@%s' % (v['type'], v['name'], v['version']))

    licenses = v['licenses']
    if len(licenses) > 0:
        print('  Licenses:')
        for l in licenses:
            print('   - %s | %s' % (l['license'], l['id']))

    deps_with_issues = v['dependenciesWithIssues']
    if len(deps_with_issues) > 0:
        print('  Deps with Issues:')
        for d in deps_with_issues:
            print('   - %s' % d)

    # print('  %s@%s' % (v['package'], v['version']))
    # print('  Severity: %s' % v['severity'])
