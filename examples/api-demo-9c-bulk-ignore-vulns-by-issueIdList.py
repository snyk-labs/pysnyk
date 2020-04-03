***REMOVED***
import json
import re
import sys
import requests
import urllib3
***REMOVED***
***REMOVED***

***REMOVED***
***REMOVED***
***REMOVED***"--orgId", type=str,
                        help="The Snyk Organisation Id", required=True)
    # Store issueId as list (--issueIdList=SNYK-JS-HANDLEBARS-173692,SNYK-JS-JSYAML-174129 as example)
***REMOVED***"--issueIdList", type=str,
                        help="The Snyk Issue IdList", required=True)
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
issue_ids = args.issueIdList.split(',') # split issue list to run the loop
reason_type = args.reasonType
time = args.expirationTime
reason = args.reason
# Regex to check if the date is valid
datere = "[2-9][0-9][0-9][0-9]-[0-2][0-9]-[0-3][0-9]"
datetimere = "[2-9][0-9][0-9][0-9]-[0-2][0-9]-[0-3][0-9]T[0-2][0-4]:[0-5][0-9]:[0-6][0-9].[0-9][0-9][0-9]Z"
expires = None
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
        # HERE
        if i["id"] in issue_ids:
            values_object = {
                "ignorePath": "",
                "reasonType": reason_type,
                "disregardIfFixable": False
            }
            if reason is not None:
                values_object["reason"] = reason
            if expires is not None:
                values_object["expires"] = expires
            api_url = "org/%s/project/%s/ignore/%s" % (org_id, proj.id , i["id"])
            r2 = client.post(api_url, values_object)
