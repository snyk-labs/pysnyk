# snyk-api-examples-python

## Get Started
You'll need Python 3.7 and [pipenv](https://pipenv.readthedocs.io/en/latest/).

```
git clone https://github.com/snyk-samples/snyk-api-examples-python.git
cd snyk-api-examples-python
pipenv install
pipenv shell
```

You will also need to create a file with path `~/.ssh/tokens/snyk-api-token` which contains a valid Snyk API token - either your [personal token](https://app.snyk.io/account) or a [service account](https://snyk.io/docs/service-accounts/) token. This file should contain the token alone with no formatting.

## Running a Script
The sample scripts are all a bit different, so you should try them each out or look at the code.

In general the form is:
```
python <script-name.py> --orgId=<your-org_id> ...
```

## Update GitHub Checks Settings
Use this to update the GitHub checks settings for a particular projectId or all GitHub projects in your Snyk org. 
```
python api-demo-11-update-github-checks.py --orgId=<your-snyk-org> --projectId=<snyk-project-id>|all --pullRequestTestEnabled=[true|false]
```

## Project Dependencies and Licenses Report
This report generates a list of all dependencies (including transitive dependencies) and all associated licenses either for a specific project within your Snyk org, or across all of them.

There are four output options; you need to chose one or more of them:
* --outputPathExcel=<desired-output-file-path>
* --outputPathCSV=<desired-output-file-path>
* --outputPathNestedJson=<desired-output-file-path>
* --outputPathFlatJson=<desired-output-file-path>

Specify a unique file / path for each option you want.

For example, if you wanted the Excel option only, you'd do something like (after completing the above Getting Started steps):
```
python api-demo-10-project-deps-licenses-report.py --orgId=<your-org_id> --outputPathExcel=my-report.xlsx
```

The `--outputPathNestedJson` is a good one if you want a fully nested Json representation of all project dependencies as opposed to all the other output options in which the dependencies are flattened to be more readable in a tabular format (but still show the complete path of each dependency).

## Testing packages

To test a Java package, use:
```
python api-demo-5-test-java-package.py --orgId=<your-org_id> --groupId=<groupId> --artifactId=<artifactId> --packageVersion=<packageVersion>
```

To test a RubyGem package, use:
```
python api-demo-5b-test-rubygem-package.py --orgId=<your-org_id> --packageName=<package-name> --packageVersion=<package-version>
```

To test a Python (pip) package, use:
```
python api-demo-5c-test-python-package.py --orgId=<your-org_id> --packageName=<package-name> --packageVersion=<package-version>
```

To test an npm package, use:
```
python api-demo-5d-test-npm-package.py --orgId=<your-org_id> --packageName=<package-name> --packageVersion=<package-version>
```
