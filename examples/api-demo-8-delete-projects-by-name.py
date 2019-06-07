***REMOVED***

from pysnyk import SnykClient
from utils import get_token


***REMOVED***
***REMOVED***
***REMOVED***'--orgId', type=str,
                        help='The Snyk Organisation Id', required=True)
***REMOVED***'--projectName', type=str,
                        help='Put in your project name as it appears in Snyk', required=True)
***REMOVED***'--projectOrigin', choices=['cli', 'github', 'github-enterprise', 'bitbucket-cloud', 'bitbucket-server',
                                                    'gitlab'], help=' Set this if you want to make sure the project is from a particular place (repo, CLI, etc)', required=False)

    args = parser.parse_args()
    return args


project_ids = []

snyk_token = get_token('snyk-api-token')
***REMOVED***
***REMOVED***
# For example, for GitHub projects it is `[org]/[repo-name]`
# For a Docker scan pushed into Snyk via `snyk monitor`, it is `docker-image|[image-name]`
project_name = args.projectName
project_origin = args.projectOrigin

***REMOVED***
json_res = client.snyk_projects_projects(org_id)
for proj in json_res['projects']:
    if project_name == proj['name'] and (proj['origin'] == project_origin or not project_origin):
        project_ids.append(proj['id'])
        # print(proj['name'])
        # print(proj['id'])


print('\nDeleting projects:')
for id in project_ids:
    print(id)
    http_response = client.snyk_projects_delete(org_id, id)
    if http_response.status_code == 200:
        print('Project ID %s deleted' % id)
