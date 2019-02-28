import json

import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


org_id = ''  # TODO: put in your org_id

# TODO: put in your project name as it appears in Snyk.
# For example, for GitHub projects it is `[org]/[repo-name]`
# For a Docker scan pushed into Snyk via `snyk monitor`, it is `docker-image|[image-name]`
project_name = ''

# TODO: Optiona. Set this if you want to make sure the project is from a particular place (repo, CLI, etc).
# If not set, it will delete projects with matching names regardless of where they are from.
# You might want to use this to if, for example, you have a project in both GitHub and GitHub Enterprize with the
# same name and you only want to delete one of them.
# Options include but not limited to:
# cli
# github
# github-enterprise
# bitbucket-cloud
# bitbucket-server
# gitlab
project_origin = ''

project_ids = []

json_res = SnykAPI.snyk_projects_projects(org_id)
for proj in json_res['projects']:
    if project_name == proj['name'] and (proj['origin'] == project_origin or not project_origin):
        project_ids.append(proj['id'])
        # print(proj['name'])
        # print(proj['id'])


print('\nDeleting projects:')
for id in project_ids:
    print(id)
    http_response = SnykAPI.snyk_projects_delete(org_id, id)
    if http_response.status_code == 200:
        print('Project ID %s deleted' % id)

