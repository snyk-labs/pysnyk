***REMOVED***
import urllib3
import json
import sys
import re
import requests


***REMOVED***
from utils import get_token, get_default_token_path


***REMOVED***
***REMOVED***
***REMOVED***"--orgId", type=str,
                        help="The Snyk Organisation Id", required=True)
***REMOVED***"--issueId", type=str,
                        help="The Snyk Issue Id", required=True)
***REMOVED***"--reasonType", type=str,
                        help="Ignore Reason Type", required=True)
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
        expires = time
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

# API call to collect every project in all of a customers orgs
http = urllib3.PoolManager()
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***

    url = "org/" + org_id + "/project/" + proj.id + "/issues"

    print(url)
    # API call to grab all of the issue
    r = client.post(url, None)

    # Converts JSON to a python dict
    parsed_input = r.json()
    print (parsed_input)
    issues = parsed_input["issues"]

    print("List the Vulnerbilities")
    print (issues["vulnerabilities"])

    for i in issues["vulnerabilities"]:
        if i["id"] == issue_id:
            values_object = {
                "ignorePath": "",
                "reasonType": reason_type,
                "disregardIfFixable": False
            }
            if reason is not None:
                values_object["reason"] = reason
            if expires is not None:
                values_object["expires"] = expires

            api_url = "org/" + org_id + "/project/" + proj.id + "/ignore/" + issue_id
            r2 = client.post(api_url, values_object)
