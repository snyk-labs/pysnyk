***REMOVED***

***REMOVED***
from utils import get_token

***REMOVED***
***REMOVED***
***REMOVED***'--orgId', type=str,
                        help='The Snyk Organisation Id', required=True)

    args = parser.parse_args()

    return args

snyk_token = get_token('snyk-api-token')
***REMOVED***
***REMOVED***  # TODO: specify --orgId=<your-org-id>

show_dependencies = True
show_projects = True


# List issues in a project
***REMOVED***
json_res = client.snyk_licenses_list_all_licenses_by_org(org_id)
print('\n\nNumber of licenses: %s' % json_res['total'])
print(json_res)
for v in json_res['results']:
    print('\nLicense: %s' % (v['id']))

    if show_dependencies:
        dependencies = v['dependencies']
        print('  Dependencies:')
        for d in dependencies:
            print('   - %s: %s' % (d['packageManager'], d['id']))

    if show_projects:
        projects = v['projects']
        print('  Projects:')
        for p in projects:
            print('   - %s' % p['name'])

    # print('  %s@%s' % (v['package'], v['version']))
    # print('  Severity: %s' % v['severity'])

