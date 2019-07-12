***REMOVED***
from distutils import util
import json


***REMOVED***
from utils import get_token


***REMOVED***
***REMOVED***
***REMOVED***
        "--orgId", type=str, help="The Snyk Organisation Id", required=True
***REMOVED***
***REMOVED***
        "--projectId", type=str, help="The project ID in Snyk, use 'all' to execute for all projects.", required=True
***REMOVED***
***REMOVED***
        "--pullRequestTestEnabled",
        type=lambda x: bool(util.strtobool(x)),
        help="Whether or not you want to enable PR checks [true|false]",
        required=True,
***REMOVED***
***REMOVED***


snyk_token = get_token("snyk-api-token")
***REMOVED***
***REMOVED***
project_id = args.projectId
pullRequestTestEnabled = args.pullRequestTestEnabled


project_settings = {"pullRequestTestEnabled": pullRequestTestEnabled}

client = SnykClient(snyk_token)
projects = client.organizations.get(org_id).projects.all()

github_projects = [
    {"id": p.id, "name": p.name}
    for p in projects
    if p.origin == "github"
]

def get_project_by_id(projects, project_id):
    for project in projects:
        if project.id == project_id:
            return project


for proj in github_projects:
    if project_id == proj["id"] or project_id == "all":
        print("%s | %s" % (proj["id"], proj["name"]))
        print("  - updating project settings...")
        resp = get_project_by_id(projects, proj["id"]).settings.update(**project_settings)

        if resp:
            print("  - success: %s" % (proj["id"]))
        else:
            print("  - failed: %s" % (proj["id"]))


print("done")
