import argparse
from distutils import util
import json


from snyk import SnykClient
from utils import get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument('--orgId', type=str,
                        help='The Snyk Organisation Id', required=True)

    parser.add_argument('--projectId', type=str,
                        help='The project ID in Snyk', required=True)

    parser.add_argument('--pullRequestTestEnabled', type=lambda x:bool(util.strtobool(x)),
                        help='Whether or not you want to enable PR checks [true|false]', required=True)

    args = parser.parse_args()

    return args


snyk_token = get_token('snyk-api-token')
args = parse_command_line_args()
org_id = args.orgId
project_id = args.projectId
pullRequestTestEnabled = args.pullRequestTestEnabled


project_settings = {
    'pullRequestTestEnabled': pullRequestTestEnabled
}

client = SnykClient(token=snyk_token)
json_res = client.snyk_projects_projects(org_id)

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
        resp = client.snyk_projects_update_project_settings(org_id, proj['id'], **project_settings)

        if resp.status_code == 200:
            print('  - success: %s' % (resp.json()))
        else:
            print('  - failed: %s %s' % (resp.status_code, resp.reason))


print('done')

