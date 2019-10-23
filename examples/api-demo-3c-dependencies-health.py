import argparse
import datetime
import json
from datetime import date

from snyk import SnykClient
from utils import get_default_token_path, get_token

# *****Instructions****
# See README on where to specify snyk-api-token to authorize this example
# FOR NOW RUN export PYTHONPATH=`pwd` ON COMMAND PROMPT UNTIL PUBLISHED
# Sample commands:
#   python3 api-demo-3c-dependencies-health.py --orgId=SOMEORGID
#   python3 api-demo-3c-dependencies-health.py --orgId=SOMEORGID --projectId=PROJECTID


class analysisLog:
    ###Internal Configuration - do not modify
    supportPackageManagers = ["npm"]
    supportPackageManagersDeprecated = ["npm"]
    ###The intial version of this is focused on Major and dot version, long term rules could include multi level inspection when
    ###Format of a rule is say 3.0 to 3.0.1

    ########################################################
    ###USER MODIFIABLE RULES - MODIFY THIS TO MATCH YOUR POLICY
    ########################################################
    bCheckMajor = True
    ruleMajorDifference = 2  # x.. to z...
    bCheckMinor = True
    ruleMinorDifference = 3  # 1.x to 1.z
    bCheckDeprecated = True
    bCheckBetaInUseAndFullVersionAvailable = (
        True
    )  # Check if you are on a 0.x version but a full one 1.x or greater is available
    bCheckAge = True
    ruleDepYearsSinceLastUpdate = (
        2
    )  # Number of years since last update/release for package
    #####END RULES

    def __init__(self, neworgid, newprojectId):
        self.projectId = newprojectId
        if (newprojectId is None) or (newprojectId == ""):
            self.projectId = ""
        self.orgId = neworgid
        #####ISSUE LIST####
        self.lstDeprecatedViolationItems = []
        self.lstMajorVersionViolationItems = []
        self.lstMinorVersionViolationItems = []
        self.lstBetaInUseAndFullVersionAvailable = []
        self.lstAgePolicyViolation = []
        self.iDepsAnalyzed = 0
        self.iDepsDetected = 0
        self.debugPrint = False

    ###PRINTERS
    def print_json(self, json_obj):
        print(json.dumps(json_obj, indent=4))

    def printItemsinList(self, arrList):
        for item in arrList:
            print("\t\t" + item[0] + "\t" + item[1])

    def printIssues(self):
        print("\t----Outputting results----")
        displayProjectId = self.projectId
        if self.projectId == "":
            displayProjectId = "(NOT SPECIFIED)"

        print(
            "\t\t----ORG ID: "
            + self.orgId
            + " , PROJECT ID: "
            + displayProjectId
            + " , Dependencies Detected: "
            + str(self.iDepsDetected)
            + " , Dependencies Analyzed: "
            + str(self.iDepsAnalyzed)
            + "----"
        )

        if self.bCheckDeprecated:
            print(
                "\t----Deprecated items (Current Package, Package Manager Status)----"
            )
            self.printItemsinList(self.lstDeprecatedViolationItems)
        if self.bCheckMajor:
            print(
                "\t----Major Policy Version - Difference of "
                + str(self.ruleMajorDifference)
                + " (Current Package/Latest Package)----"
            )
            self.printItemsinList(self.lstMajorVersionViolationItems)
        if self.bCheckMinor:
            print(
                "\t----Minor Policy Version - Difference of "
                + str(self.ruleMinorDifference)
                + " (Current Package/Latest Package)----"
            )
            self.printItemsinList(self.lstMinorVersionViolationItems)
        if self.bCheckBetaInUseAndFullVersionAvailable:
            print(
                "\t----An early version in use (aka 0.X is in use when a full version is available)----"
            )
            self.printItemsinList(self.lstBetaInUseAndFullVersionAvailable)
        if self.bCheckAge:
            print(
                "\t----Library not maintained: Checking "
                + str(self.ruleDepYearsSinceLastUpdate)
                + " Years Since Last Update to this package (Package/Age in Years)----"
            )
            self.printItemsinList(self.lstAgePolicyViolation)

    ###VERSION MANIPULATION FUNCTIONS
    def parseVersions(self, sVersion):
        arrResult = sVersion.split(".")
        # Future: perform normalization operations here (i.e compare format, i.e. x.x and x.x.x of cur/latest versions for compare, this will facilitate potential patch checks)
        return arrResult

    ####POLICY LOGIC
    def checkVersion(self, curDep):
        curVersion = curDep.version
        parsedVersions = self.parseVersions(curVersion)
        majVersion = int(parsedVersions[0])
        minVersion = int(parsedVersions[1])
        latestVersion = curDep.latestVersion
        latestParsedVersions = self.parseVersions(latestVersion)
        latestMajVersion = int(latestParsedVersions[0])
        latestMinVersion = int(latestParsedVersions[1])

        if self.bCheckMajor:
            majDiff = latestMajVersion - majVersion
            if majDiff >= self.ruleMajorDifference:
                newList = [curDep.name + "@" + curDep.version, latestVersion]
                self.lstMajorVersionViolationItems.append(newList)

        if self.bCheckMinor:
            minDiff = latestMinVersion - minVersion
            if (latestMajVersion == majVersion) and (
                minDiff >= self.ruleMinorDifference
            ):
                newList = [curDep.name + "@" + curDep.version, latestVersion]
                self.lstMinorVersionViolationItems.append(newList)

    def checkDeprecated(self, curDep):
        if curDep.packageManager in self.supportPackageManagersDeprecated:
            if curDep.isDeprecated:
                newList = [
                    curDep.name + "@" + curDep.version,
                    curDep.packageManager + ": DEPRECATED",
                ]
                self.lstDeprecatedViolationItems.append(newList)
        else:
            print("Type: " + curDep.packageManager)

    def checkBetaInUseAndFullVersionAvailable(self, curDep):
        # Future - also look for 'release candidate' and 'beta' type tags and if there is a newer version released
        curVersion = curDep.version
        parsedVersions = self.parseVersions(curVersion)
        majVersion = int(parsedVersions[0])
        latestVersion = curDep.latestVersion
        latestParsedVersions = self.parseVersions(latestVersion)
        latestMajVersion = int(latestParsedVersions[0])

        if self.bCheckBetaInUseAndFullVersionAvailable:
            if (majVersion == 0) and (latestMajVersion > 0):
                newList = [curDep.name + "@" + curDep.version, latestVersion]
                self.lstBetaInUseAndFullVersionAvailable.append(newList)

    def CalculateAgeInYears(self, dateToCompare):
        today = date.today()
        arrDateTime = dateToCompare.split("T")
        sDateOnly = arrDateTime[0]
        inputDate = datetime.datetime.strptime(sDateOnly, "%Y-%m-%d")
        age = (
            today.year
            - inputDate.year
            - ((today.month, today.day) < (inputDate.month, inputDate.day))
        )
        return age

    def checkAgeViolation(self, curDep):
        if self.bCheckAge:
            detectedAgeYearsOld = self.CalculateAgeInYears(
                curDep.latestVersionPublishedDate
            )
            if detectedAgeYearsOld >= self.ruleDepYearsSinceLastUpdate:
                newList = [curDep.name, str(detectedAgeYearsOld)]
                if newList not in self.lstAgePolicyViolation:
                    self.lstAgePolicyViolation.append(newList)

    def validatePolicy(self, depToCheck):
        if (self.bCheckMajor == True) or (self.bCheckMinor == True):
            self.checkVersion(depToCheck)
        if self.bCheckDeprecated == True:
            self.checkDeprecated(depToCheck)
        if self.bCheckBetaInUseAndFullVersionAvailable == True:
            self.checkBetaInUseAndFullVersionAvailable(depToCheck)
        if self.bCheckAge == True:
            self.checkAgeViolation(depToCheck)

    def analyze(self, depResults):
        for curDep in depResults:
            self.iDepsDetected += 1
            if curDep.packageManager in self.supportPackageManagers:
                self.iDepsAnalyzed += 1
                self.validatePolicy(curDep)


##END CLASS


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument("--orgId", type=str, help="The Snyk Organisation Id")

    parser.add_argument("--projectId", type=str, help="The project ID in Snyk")

    args = parser.parse_args()

    if args.orgId is None:
        parser.error("You must specify --orgId")

    # Make this optional for compliance reasons, we want to allow checks across all projects
    # if args.projectId is None:
    #    parser.error('You must specify --projectId')

    return args


args = parse_command_line_args()
org_id = args.orgId
project_id = args.projectId

# List issues in a project
print("----FETCHING DATA----")
snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
client = SnykClient(snyk_token)

deps = client.organizations.get(org_id).projects.get(project_id).dependencies.all()

print("----DATA FETCHED----")
print("----STARTING ANALYSIS----")
if len(deps) > 0:
    logObj = analysisLog(org_id, project_id)
    logObj.analyze(deps)
    logObj.printIssues()
else:
    print("\n\tNO DATA FOUND")

print("\n\n---ANALYSIS COMPLETE---\n\n")
