import json

import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


org_id = ''  # TODO: put in your org_id

github_org = ''  # TODO: put in your github org name

# TODO: Put in your repo name. For example, for GitHub projects it is `[org]/[repo-name]`
project_name = ''

# TODO - Put in your GitHub integration ID - get this from Settings->Integrations
github_integration_id = ''


# TODO: Leave this empty to import all or make a list of paths/to/build/files (ex 'build.gradle' or 'someModule/pom.xml')
manifest_files = [
]

project_ids = []

# List projects in org
http_resp = SnykAPI.snyk_integrations_import(org_id, github_integration_id, github_org, project_name, manifest_files)
if http_resp.status_code == 201:
    print('Project imported or already exists')
    print('%s %s' % (http_resp.status_code, http_resp.reason))
else:
    print('Failed importing project')
    print(http_resp.status_code)
    print(http_resp.reason)
    print(http_resp)

