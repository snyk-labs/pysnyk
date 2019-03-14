# snyk-api-examples-python

## Get Started
You'll need Python 3.7 and [pipenv](https://pipenv.readthedocs.io/en/latest/).

```
git clone https://github.com/snyk-samples/snyk-api-examples-python.git
cd snyk-api-examples-python
pipenv install
pipenv shell
```

## Running a Script
The sample scripts are all a bit different, so you should try them each out or look at the code.

In general the form is:
```
python <script-name.py> --orgId=<your-org_id> ...
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
