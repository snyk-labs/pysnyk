***REMOVED***
import urllib3
import json
import sys
import re


***REMOVED***
from utils import get_token, get_default_token_path


***REMOVED***
***REMOVED***
***REMOVED***'--orgId', type=str,
                        help='The Snyk Organisation Id', required=True)
***REMOVED***'--issueId', type=str,
                        help='The Snyk Issue Id', required=True)
***REMOVED***'--reasonType', type=str,
                        help='Ignore Reason Type', required=True)
***REMOVED***"--expirationTime", type=str,
                        help="Optional. Expiration time of ignore. e.g. yyyy-mm-dd or yyyy-mm-ddThh:mm:ss.aaaZ",)
***REMOVED***"--reason", type=str,
                        help="Optional. Reason for ignoring e.g. \"We do not use this library.\"",)
    args = parser.parse_args()

    return args


***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
issue_id = args.issueId
reason_type = args.reasonType
time = args.expirationTime
reason = args.reason

# Regex to check if the date is valid
datere = "[2-9][0-9][0-9][0-9]-[0-2][0-9]-[0-3][0-9]"
datetimere = "[2-9][0-9][0-9][0-9]-[0-2][0-9]-[0-3][0-9]T[0-2][0-4]:[0-5][0-9]:[0-6][0-9].[0-9][0-9][0-9]Z"

# Logic to check if a reason and/or time was added
if time is None:
    confirm = 0
else:
    if re.match(datere, time) or re.match(datetimere, time):
        print("Valid Time Arguments")
        confirm = 1
    else:
        print("Please use a date in yyyy-mm-ddThh or yyyy-mm-ddThh:mm:ss.aaaZ format")
        sys.exit()

if reason is None:
    print("No reason given")
else:
    if confirm == 1:
        print("Reason given!")
        confirm = 2
    else:
        confirm = 3

***REMOVED***

headers = {
    'Content-Type': 'application/json',
    'Authorization': 'token %s' % snyk_token
}

# API call to collect every project in all of a customers orgs
http = urllib3.PoolManager()
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***

    p1 = 'https://snyk.io/api/v1/org/'
    p2 = '/project/'
    p3 = '/issues'
    url = p1 + org_id + p2 + proj.id + p3

    print(url)
    # API call to grab all of the issue
    r = http.request('POST', url, headers=headers)

    # Converts JSON to a python dict
    parsed_input = json.loads(r.data)
    print (parsed_input)
    issues = parsed_input['issues']

    print(r.data)
    print('List the Vulnerbilities')
    print (issues['vulnerabilities'])

    for i in issues['vulnerabilities']:
        if confirm == 0:
            values = """
            {
                "ignorePath": "",
                "reason": "",
                "reasonType": "%s",
                "disregardIfFixable": false
            }
            """ % reason_type
            if i['id'] == issue_id:
                p4 = '/ignore/'
                url2 = p1 + org_id + p2 + proj.id + p4 + issue_id
                # ignore vulnerability
                r2 = http.request('POST', url2, body=values, headers=headers)
                print(r2.data, r2.status)

        if confirm == 1:
            values = """
            {
                "ignorePath": "",
                "reason": "",
                "reasonType": "%s",
                "disregardIfFixable": false,
                "expires": "%s"
            }
            """ % (reason_type, time)

            if i['id'] == issue_id:
                p4 = '/ignore/'
                url3 = p1 + org_id + p2 + proj.id + p4 + issue_id
                # ignore vulnerability
                r3 = http.request('POST', url3, body=values, headers=headers)
                print(r3.data, r3.status)

        if confirm == 2:
            values = """
            {
                "ignorePath": "",
                "reason": "%s",
                "reasonType": "%s",
                "disregardIfFixable": false,
                "expires": "%s"
            }
            """ % (reason, reason_type, time)

            if i['id'] == issue_id:
                p4 = '/ignore/'
                url3 = p1 + org_id + p2 + proj.id + p4 + issue_id
                # ignore vulnerability
                r3 = http.request('POST', url3, body=values, headers=headers)
                print(r3.data, r3.status)

        if confirm == 3:
            values = """
            {
                "ignorePath": "",
                "reason": "%s",
                "reasonType": "%s",
                "disregardIfFixable": false,
            }
            """ % (reason, reason_type)

            if i['id'] == issue_id:
                p4 = '/ignore/'
                url3 = p1 + org_id + p2 + proj.id + p4 + issue_id
                # ignore vulnerability
                r3 = http.request('POST', url3, body=values, headers=headers)
                print(r3.data, r3.status)
