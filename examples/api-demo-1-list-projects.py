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


# List projects in org
***REMOVED***
json_res = client.snyk_projects_projects(org_id)
for proj in json_res['projects']:
    print('\nProject Name: %s' % proj['name'])
    print('  Issues Found:')
    print('      High  : %s' % proj['issueCountsBySeverity']['high'])
    print('      Medium: %s' % proj['issueCountsBySeverity']['medium'])
    print('      Low   : %s' % proj['issueCountsBySeverity']['low'])

