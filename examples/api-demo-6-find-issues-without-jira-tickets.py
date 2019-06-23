***REMOVED***

from pysnyk import SnykClient
from utils import get_token


***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
        "--projectId", type=str, help="The Snyk Project ID", required=True
***REMOVED***
***REMOVED***


snyk_token = get_token("snyk-api-token")
***REMOVED***
***REMOVED***
project_id = args.projectId

client = SnykClient(snyk_token)
project = client.organization(org_id).project(project_id)
issues = project.issues.issues
jira_issues = project.jira_issues

all_issue_ids = []
all_issue_ids.extend([i.id for i in issues.vulnerabilities])
all_issue_ids.extend([i.id for i in issues.licenses])

snyk_issue_with_jira_issues = list(jira_issues.keys())

for issue in issues.vulnerabilities + issues.licenses:
    if issue.id not in list(jira_issues.keys()):
        print("Found issue without Jira issue: %s" % issue.id)
        print(
            "  https://app.snyk.io/org/%s/project/%s#%s"
            % (org_id, project_id, issue.id)
    ***REMOVED***
