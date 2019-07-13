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
    return parser.parse_args()


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId
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
        )
