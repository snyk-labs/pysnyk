import argparse

from snyk import SnykClient
from utils import get_default_token_path, get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation ID", required=True
    )
    parser.add_argument(
        "--projectId", type=str, help="The Snyk Project ID", required=True
    )
    parser.add_argument(
        "--jiraProjectId", type=int, help="The Jira Project ID", required=True
    )
    parser.add_argument(
        "--jiraIssueType", type=int, help="The Jira issue type", required=True
    )
    return parser.parse_args()


def create_jira_issue(project, issue, jira_project, issuetype):
    return project.jira_issues.create(issue.id, {"project": {"id": jira_project}, "issuetype": {"id": issuetype}, "summary": "%s - %s" % (project.name, issue.title)})


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId
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
