import requests
import json
from pathlib import Path


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


def requests_do_post_api_return_json_object(api_url, obj_json_post_body):
    snyk_post_api_headers = snyk_api_headers
    snyk_post_api_headers['Content-type'] = 'application/json'

    resp = requests.post(api_url, json=obj_json_post_body, headers=snyk_api_headers)
    return resp.json()


def get_token(token_name):
    home = str(Path.home())

    path = '%s/.ssh/tokens/%s' % (home, token_name)

    with open(path) as f:
        read_data = f.read()
        token = str.strip(read_data)
        return token
    f.closed


snyk_api_base_url = 'https://snyk.io/api/v1/'
snyk_token = get_token('snyk-api-token')
snyk_api_headers = {
    'Authorization': 'token %s' % snyk_token
}


###########
# API functions organized per Snyk API Structure
###########

# Groups

# Organizations

# Organizations -> orgs
# Lists all Organizations a User belongs to
# Status: not working - something weird going on where I don't have the permissions to see my orgs
def snyk_organizations_orgs():
    full_api_url = '%sorgs' % (snyk_api_base_url)

    print(full_api_url)
    # print(snyk_api_headers)
    # quit()

    print('calling api...')

    resp = requests.get(full_api_url, headers=snyk_api_headers)
    obj_json_response_content = resp.json()
    print_json(obj_json_response_content)


# Organizations -> List Members
# https://snyk.docs.apiary.io/#reference/organisations/members-in-organisation/list-members
def snyk_organizations_list_members(org_id):
    full_api_url = '%sorg/%s/members' % (snyk_api_base_url, org_id)
    print(full_api_url)

    resp = requests.get(full_api_url, headers=snyk_api_headers)
    obj_json_response_content = resp.json()
    print_json(obj_json_response_content)


# Projects

# Projects -> List All Projects
# https://snyk.docs.apiary.io/#reference/projects/all-projects/list-all-projects
def snyk_projects_projects(org_id):
    full_api_url = '%sorg/%s/projects' % (snyk_api_base_url, org_id)

    resp = requests.get(full_api_url, headers=snyk_api_headers)
    obj_json_response_content = resp.json()
    print_json(obj_json_response_content)
    return obj_json_response_content


# Projects -> List All Issues
# https://snyk.docs.apiary.io/#reference/projects/project-issues
# org_id works either like 'demo-applications' or the big hash
def snyk_projects_project_issues(org_id, project_id):
    full_api_url = '%sorg/%s/project/%s/issues' % (snyk_api_base_url, org_id, project_id)
    # print(full_api_url)

    post_body = {
        'filters': {
            'severities': ['high', 'medium', 'low'],
            'types': ['vuln', 'license'],
            'ignored': False,
            'patched': False
        }
    }

    # json_text = json.dumps(post_body, indent=4)
    # print(json_text)

    # raw_data = '{ "filters": { "severities": ["high","medium","low"], "types": ["vuln","license"], "ignored": false, "patched": false } }'

    obj_json_response_content = requests_do_post_api_return_json_object(full_api_url, post_body)
    # print_json_object(obj_json_response_content)

    json_text = json.dumps(obj_json_response_content, indent=4)

    # with open("response.json", "w") as text_file:
    #     text_file.write(json_text)

    # resp = requests.get(full_api_url, headers=snyk_api_headers)

    # print_json(obj_json_response_content)
    return obj_json_response_content


def snyk_projects_project_jira_issues_list_all_jira_issues(org_id, project_id):
    full_api_url = '%sorg/%s/project/%s/jira-issues' % (snyk_api_base_url, org_id, project_id)

    resp = requests.get(full_api_url, headers=snyk_api_headers)
    obj_json_response_content = resp.json()
    # print_json(obj_json_response_content)
    return obj_json_response_content


# Dependencies

# Dependencies -> List All Dependencies
# https://snyk.docs.apiary.io/#reference/dependencies/dependencies-by-organisation
def snyk_dependencies_list_all_dependencies_by_project(org_id, project_id):
    full_api_url = '%sorg/%s/dependencies?sortBy=dependency&order=asc&page=1&perPage=50' % (snyk_api_base_url, org_id)
    print(full_api_url)

    post_body = {
        'filters': {
            'projects': [ project_id]
        }
    }

    # json_text = json.dumps(post_body, indent=4)
    # print(json_text)

    # raw_data = '{ "filters": { "severities": ["high","medium","low"], "types": ["vuln","license"], "ignored": false, "patched": false } }'

    obj_json_response_content = requests_do_post_api_return_json_object(full_api_url, post_body)
    # print_json_object(obj_json_response_content)

    json_text = json.dumps(obj_json_response_content, indent=4)

    # with open("response.json", "w") as text_file:
    #     text_file.write(json_text)

    # resp = requests.get(full_api_url, headers=snyk_api_headers)

    print_json(obj_json_response_content)
    return obj_json_response_content



# Licenses
# List all licenses (in an org)
# https://snyk.docs.apiary.io/#reference/licenses/licenses-by-organisation
def snyk_licenses_list_all_licenses_by_org(org_id):
    full_api_url = '%sorg/%s/licenses?sortBy=license&order=asc' % (snyk_api_base_url, org_id)

    post_body = {
        'filters': {
        }
    }

    obj_json_response_content = requests_do_post_api_return_json_object(full_api_url, post_body)
    return obj_json_response_content


# Tests

# Tests -> test maven
# https://snyk.docs.apiary.io/#reference/test/maven/test-for-issues-in-a-public-package-by-group-id,-artifact-id-and-version
def snyk_test_maven(package_group_id, package_artifact_id, version, org_id):
    full_api_url = '%stest/maven/%s/%s/%s?org=%s' % (
    snyk_api_base_url, package_group_id, package_artifact_id, version, org_id)
    resp = requests.get(full_api_url, headers=snyk_api_headers)
    obj_json_response_content = resp.json()
    return obj_json_response_content

