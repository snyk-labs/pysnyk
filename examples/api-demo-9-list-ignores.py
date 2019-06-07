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
***REMOVED***


show_dependencies = True
show_projects = True

***REMOVED***
json_res_projects = client.snyk_projects_projects(org_id)
for proj in json_res_projects['projects']:
    project_id = proj['id']
    project_name = proj['name']

    json_res_ignores = client.snyk_projects_list_all_ignores(org_id, project_id)

    if len(json_res_ignores.keys()) > 0:
        # issues exist for this project

        print('Project ID: %s' % project_id)
        print('Project Name: %s' % project_name)

        for next_issue_id in json_res_ignores.keys():
            print('  Ignored Issue ID: %s' % next_issue_id)
            next_issue_ignores = json_res_ignores[next_issue_id]

            for next_ignore in next_issue_ignores:

                for i_key in next_ignore.keys():
                    # print('    %s ' % i_key)  # Not sure why this is a dictionary - they is always *
                    i_value = next_ignore[i_key]
                    # print(i_value)

                    reason = i_value['reason']
                    created_date = i_value['created']
                    expires_date = i_value['expires']
                    ignored_by_user = i_value['ignoredBy']
                    ignored_by_id = ignored_by_user['id']
                    ignored_by_name = ignored_by_user['name']
                    ignored_by_email = ignored_by_user['email']
                    reason_type = i_value['reasonType']
                    disregard_if_fixable = i_value['disregardIfFixable']
                    print('    Ignore reason: %s ' % reason)
                    print('    Ignore created: %s ' % created_date)
                    print('    Ignore expires: %s ' % expires_date)
                    print('    Ignored by (User ID): %s ' % ignored_by_id)
                    print('    Ignored by (name): %s ' % ignored_by_name)
                    print('    Ignored by (email) %s ' % ignored_by_email)
                    print('    Ignore type: %s ' % reason_type)
                    print('    Ignore is disregard if fixable: %s ' % disregard_if_fixable)

        print('\n')

