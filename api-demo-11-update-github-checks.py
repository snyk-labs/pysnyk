***REMOVED***
from distutils import util
import json


import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


***REMOVED***
***REMOVED***
***REMOVED***'--orgId', type=str,
                        help='The Snyk Organisation Id')

***REMOVED***'--projectId', type=str,
                        help='The project ID in Snyk')

***REMOVED***'--pullRequestTestEnabled', type=lambda x:bool(util.strtobool(x)),
                        help='Whether or not you want to enable PR checks')

    args = parser.parse_args()

    if args.orgId is None:
        parser.error('You must specify --orgId')

    if args.projectId is None:
        parser.error('You must specify --projectId. use --projectId=all to update all GitHub projects in your Snyk org')

    if args.pullRequestTestEnabled is None:
        parser.error('You must specify --pullRequestTestEnabled=[true|false]')

    return args


***REMOVED***
***REMOVED***
project_id = args.projectId
pullRequestTestEnabled = args.pullRequestTestEnabled


project_settings = {
    'pullRequestTestEnabled': pullRequestTestEnabled
}

json_res = SnykAPI.snyk_projects_projects(org_id)

github_projects = [
    {
        'id': p['id'],
        'name': p['name']
    }
    for p in json_res['projects']
    if p['origin'] == 'github'
]

for proj in github_projects:
    if project_id == proj['id'] or project_id == 'all':
        print('%s | %s' % (proj['id'], proj['name']))
        print('  - updating project settings...')
        resp = SnykAPI.snyk_projects_update_project_settings(org_id, proj['id'], **project_settings)

        if resp.status_code == 200:
            print('  - success: %s' % (resp.json()))
        else:
            print('  - failed: %s %s' % (resp.status_code, resp.reason))


print('done')

