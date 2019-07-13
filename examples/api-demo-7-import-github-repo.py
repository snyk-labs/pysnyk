***REMOVED***

***REMOVED***
***REMOVED***


***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
        "--githubOrg", type=str, help="The GitHub organization name", required=True
***REMOVED***
***REMOVED***
        "--repoName", type=str, help="The GitHub repository name", required=True
***REMOVED***
***REMOVED***
        "--githubIntegrationId",
        type=str,
        help="GitHub integration ID - get this from Settings->Integrations",
        required=True,
***REMOVED***
***REMOVED***
        "--manifestFiles",
        nargs="*",
        help='Leave this empty to import all or make a list of paths/to/build/files (ex "build.gradle" or "someModule/pom.xml")',
        required=False,
***REMOVED***
***REMOVED***


***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
github_org = args.githubOrg
repo_name = args.repoName
github_integration_id = args.githubIntegrationId
manifest_files = args.manifestFiles

client = SnykClient(snyk_token)
org = client.organizations.get(org_id)
integration = org.integrations.get(github_integration_id)
if manifest_files:
    job = integration.import_git(github_org, repo_name, files=manifest_files)
else:
    job = integration.import_git(github_org, repo_name)

print(job)
