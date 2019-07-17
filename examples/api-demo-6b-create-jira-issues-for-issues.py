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
        "--jiraProjectId", type=int, help="The Jira Project ID", required=True
***REMOVED***
***REMOVED***
        "--jiraIssueType", type=int, help="The Jira issue type", required=True
***REMOVED***
***REMOVED***


def create_jira_issue(project, issue, jira_project, issuetype):
    return project.jira_issues.create(issue.id, {"project": {"id": jira_project}, "issuetype": {"id": issuetype}, "summary": "%s - %s" % (project.name, issue.title)})


***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
project_id = args.projectId
jira_project_id = args.jiraProjectId
jira_issue_type = args.jiraIssueType

client = SnykClient(snyk_token)
org = client.organizations.get(org_id)
project = org.projects.get(project_id)
issues = project.issueset.all().issues
jira_issues = project.jira_issues.all()

snyk_issue_with_jira_issues = list(jira_issues.keys())

for issue in issues.vulnerabilities + issues.licenses:
    if issue.id not in list(jira_issues.keys()):
        print("Creating Jira issue for Snyk issue: %s" % issue.id)
        jira_issue = create_jira_issue(project, issue, jira_project_id, jira_issue_type)
        print("Created: [%s] - [%s]" % (jira_issue["id"], jira_issue["key"]))