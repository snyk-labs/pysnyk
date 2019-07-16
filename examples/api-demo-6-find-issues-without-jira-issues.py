***REMOVED***

***REMOVED***
from utils import get_token, get_default_token_path


***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
        "--projectId", type=str, help="The Snyk Project ID", required=True
***REMOVED***
***REMOVED***


***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
project_id = args.projectId

client = SnykClient(snyk_token)
org = client.organizations.get(org_id)
project = client.organizations.get(org_id).projects.get(project_id)
issues = project.issueset.all().issues
jira_issues = project.jira_issues.all()

snyk_issue_with_jira_issues = list(jira_issues.keys())

for issue in issues.vulnerabilities + issues.licenses:
    if issue.id not in list(jira_issues.keys()):
        print("Found issue without Jira issue: %s" % issue.id)
        print(
            "  https://app.snyk.io/org/%s/project/%s#%s"
            % (org.name, project_id, issue.id)
    ***REMOVED***
