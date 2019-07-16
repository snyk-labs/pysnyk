***REMOVED***

***REMOVED***
from utils import get_token
from utils import get_default_token_path


***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
        "--projectName",
        type=str,
        help="Put in your project name as it appears in Snyk",
        required=True,
***REMOVED***
***REMOVED***
        "--projectOrigin",
        choices=[
            "cli",
            "github",
            "github-enterprise",
            "bitbucket-cloud",
            "bitbucket-server",
            "gitlab",
        ],
        help=" Set this if you want to make sure the project is from a particular place (repo, CLI, etc)",
        required=False,
***REMOVED***
***REMOVED***


***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
# For example, for GitHub projects it is `[org]/[repo-name]`
# For a Docker scan pushed into Snyk via `snyk monitor`, it is `docker-image|[image-name]`
project_name = args.projectName
project_origin = args.projectOrigin

client = SnykClient(snyk_token)
for project in client.organizations.get(org_id).projects.all():
    if project_name == project.name and (
        project.origin == project_origin or not project_origin
***REMOVED***:
        if project.delete():
            print("Project ID %s deleted" % project.id)
