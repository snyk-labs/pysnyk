import argparse
import collections
import json
import operator
from collections import OrderedDict

from snyk import SnykClient
from utils import get_default_token_path, get_token

# ****Instructions******
# See README on where to specify snyk-api-token to authorize this example
# FOR NOW RUN export PYTHONPATH=`pwd` ON COMMAND PROMPT UNTIL PUBLISHED
# SAMPLE RUN COMMAND:
#   python3 examples/api-demo-2b-issues-analytics.py --orgID=YOURORGIDHERE --projectID=YOURSNYKPROJECTID

org_id = ""
project_id = ""
json_rslts_repo = ""


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument("--orgId", type=str, help="The Snyk Organisation Id")

    parser.add_argument("--projectId", type=str, help="The project ID in Snyk")

    args = parser.parse_args()

    if args.orgId is None:
        parser.error("You must specify --orgId")

    if args.projectId is None:
        parser.error("You must specify --projectId")

    return args


args = parse_command_line_args()
org_id = args.orgId
project_id = args.projectId

###START CLASS
class analysisLog:
    iCritical = 0
    iHigh = 1
    iMedium = 2
    iLow = 3
    arrSevDescriptions = ["Critical (CVSS 9.0 and Above)", "High", "Medium", "Low"]
    # special convention for deps
    iDepByCriticalSev = 0
    iDepByHighSev = 1
    iDepIssueCounts = 2
    sDepDescriptions = [
        "By Number of Critical Severity Issues",
        "By High Severity Issues",
        "By Total Issue Count",
    ]

    def __init__(self, analysisObjID, reponame):
        # license and issue management
        self.id = analysisObjID
        self.reponame = reponame
        self.vulnIssueCounts = [0, 0, 0, 0]
        self.licenseIssueCounts = [0, 0, 0, 0]
        self.dictVulnIssues = [{}, {}, {}, {}]
        self.dictLicenseIssues = [{}, {}, {}, {}]
        self.vulnIssueTotal = 0
        self.licenseIssueTotal = 0
        self.newsIssueTotal = 0

        # special convention for deps
        self.dictDepIssues = [
            {},
            {},
            {},
        ]  # dictDepCritical,dictDepHigh,dictDepIssueCount

        ###DICTIONAIRY OF NEWS WORTHY ATTACKS####
        # Searchlist
        self.cveWatchlist = {}
        # Description for printing - (ToDo: Read from file later)
        self.cveWatchlist["CVE-2018-1000851"] = "Copay Bitcoin attack via Event-Stream"
        self.cveWatchlist["CVE-2017-5638"] = "Equifax vulnerability via Struts"
        self.cveWatchlist["CVE-2018-1002204"] = "Zip Slip - Found by Snyk!"

        ########################################
        self.cveWatchlistFound = {}
        ###Call to Action
        # self.callToAction = [CVSS, issue, isOnWatchlist,packagemanager,package@version, package@update]
        self.callToAction = [0, "", False, "", "", ""]
        self.fixableNewsStoryFound = False
        self.fixFound = False

    # Utilities
    def manageDict(self, dict, key):
        if self.keyExists(dict, key):
            dict[key] += 1
        else:
            dict[key] = 1
        return dict

    def keyExists(self, dict, key):
        if key in dict:
            return True
        else:
            return False

    def printDict(self, title, dict, isNumber):
        if title != "":
            print(title)
        for key in dict:
            if isNumber == True:
                print("\t\tIssue: " + key + " , Count:" + str(dict[key]))
            else:
                print("\t\tIssue: " + key + " , Count:" + dict[key])
        if len(dict) == 0:
            print("\t\tNone found")

    def printDictWithDescriptDict(self, title, dictItems, dictDescription):
        if title != "":
            print(title)
        for key in dictItems:
            print(
                "\t\t"
                + key
                + " , "
                + dictDescription[key]
                + ", Count: "
                + str(dictItems[key])
            )
        if len(dictItems) == 0:
            print("\t\tNone found")

    def printTopDict(self, title, dict, isNumber, limiter):
        counter = 0
        if title != "":
            print(title)
        for key in dict:
            counter += 1
            if counter > limiter:
                break
            if isNumber == True:
                print("\t\tIssue: " + key + " , Count:" + str(dict[key]))
            else:
                print("\t\tIssue: " + key + " , Count:" + dict[key])
        if len(dict) == 0:
            print("\t\tNone found")

    def sortDict(self, dict):
        sDictOrdered = OrderedDict(
            sorted(dict.items(), key=lambda x: x[1], reverse=True)
        )
        return sDictOrdered

    ##OUTPUT FUNCTIONS
    def printResultVulns(self):
        print("\nVULNERABILITY ANALYSIS")
        totalCount = (
            self.vulnIssueCounts[self.iHigh]
            + self.vulnIssueCounts[self.iMedium]
            + self.vulnIssueCounts[self.iLow]
        )
        print(
            "\n\t\tTotal Count (High, Medium, Low): "
            + str(totalCount)
            + " , Calculated Critical Severity (CVSS 9.0 and above): "
            + str(self.vulnIssueCounts[self.iCritical])
            + ", High Severity: "
            + str(self.vulnIssueCounts[self.iHigh])
            + ", Medium Severity: "
            + str(self.vulnIssueCounts[self.iMedium])
            + ", Low Severity: "
            + str(self.vulnIssueCounts[self.iLow])
        )

        for iSev in range(0, 4):
            self.printTopDict(
                "\n\t" + self.arrSevDescriptions[iSev] + " Severity Issues: ",
                self.sortDict(self.dictVulnIssues[iSev]),
                True,
                5,
            )

    def printResultLicense(self):
        print("\nLICENSE ANALYSIS")
        print(
            "\n\tHigh Severity: "
            + str(self.licenseIssueCounts[self.iHigh])
            + ", Medium Severity: "
            + str(self.licenseIssueCounts[self.iMedium])
            + ", Low Severity: "
            + str(self.licenseIssueCounts[self.iLow])
        )
        for iSev in range(1, 4):
            self.printTopDict(
                "\n\t" + self.arrSevDescriptions[iSev] + " Severity Issues: ",
                self.sortDict(self.dictLicenseIssues[iSev]),
                True,
                5,
            )

    def printResultDependency(self):
        print("\nDEPENDENCY ANALYSIS")
        print(
            "The following lists are identifying what dependencies are problematic by having critical vulns, the most high severity or the most overall count of issues (because even medium/low have value)"
        )
        for iDepIssueType in range(0, 3):
            self.printTopDict(
                "\n\tDependency by " + self.sDepDescriptions[iDepIssueType] + ": ",
                self.sortDict(self.dictDepIssues[iDepIssueType]),
                True,
                5,
            )

    def printNewsIssues(self):
        print("\n\n****CVE Watchlist***")
        print(
            "The following issues are currently critical vulnerabilities that have made the news and were found to be in your codebase"
        )
        self.printDictWithDescriptDict("", self.cveWatchlistFound, self.cveWatchlist)

    def printCallToAction(self):
        print("\n\n\t\t****Call To Action***")
        print(
            "\t\t\t A fix was found! The fix for the highest severity fixable issue is:"
        )
        print("\t\t\t\tPackage Manager: " + self.callToAction[3])
        print(
            "\t\t\t\tUpgrade: " + self.callToAction[4] + " to " + self.callToAction[5]
        )
        print("\t\t\t\tFixes: " + self.callToAction[1])
        print("\t\t\t\tCVSS: " + str(self.callToAction[0]))
        if self.callToAction[2]:
            print("\t\t\t\t***This was on our CVE Watchlist!***")

    def printResults(self):
        print("****Analysis****")
        print("\tID:" + self.id)
        if self.reponame != "":
            print("\tRepo/Project: " + self.reponame)
        if (self.vulnIssueTotal > 0) or (self.licenseIssueTotal > 0):
            print(
                "\n\n\tThe following analysis lists top 5 items in each area of analysis. Calculation was performed without grouping of vulnerabilities, highlighting every path to each vulnerability"
            )
        if self.vulnIssueTotal > 0:
            self.printResultVulns()
            self.printResultDependency()
        if self.licenseIssueTotal > 0:
            self.printResultLicense()
        if self.newsIssueTotal > 0:
            self.printNewsIssues()
        if self.fixFound:
            self.printCallToAction()
        print("\n\n***END ANALYSIS***")

    def findCVESInWatchList(self, curDep):  # returnsEmptyIfNotFound
        curCVEList = curDep.identifiers["CVE"]
        retValue = ""
        for curCVE in curCVEList:
            if self.keyExists(self.cveWatchlist, curCVE):
                retValue = curCVE
        return retValue

    def checkCallToAction(self, curDep):
        tmpUpgradePath = ""
        curIsOnWatchlist = False
        if (
            self.fixableNewsStoryFound == False
        ):  # check if a news story has been found, if it has, exit, you have your call to action
            if (
                curDep.cvssScore > self.callToAction[0]
            ):  # current issue being looked at is more severe than previous found
                if (curDep.isUpgradable) or (
                    curDep.isPatchable
                ):  # check if a fix is available
                    if curDep.isUpgradable:  # otherwise no upgrade path

                        if (
                            curDep.upgradePath[0] != curDep.fromPackages[0]
                        ):  # not a dependency install issue
                            tmpUpgradePath = curDep.upgradePath[0]
                        # else reinstall dependencies
                        # Bail - this shouldn't be listed
                    else:
                        if self.keyExists(curDep, "patches"):
                            if len(curDep.patches) > 0:  # patches found
                                tmpUpgradePath = "A custom patch developed/delivered via fix PR or run Snyk Wizard to Apply Snyk Patch!"

                if tmpUpgradePath != "":  # upgrade found
                    tmpCVE = self.findCVESInWatchList(curDep)
                    if tmpCVE != "":  # WatchlistItemFound
                        curIsOnWatchlist = True
                        self.fixableNewsStoryFound = True
                    self.callToAction = [
                        curDep.cvssScore,
                        curDep.title,
                        curIsOnWatchlist,
                        curDep.packageManager,
                        curDep.fromPackages[0],
                        tmpUpgradePath,
                    ]
                    self.fixFound = True

    # Analysis worker
    def analyzeRepo(self, issueset):
        for v in issueset.all().issues.vulnerabilities:
            self.manageDict(
                self.dictDepIssues[self.iDepIssueCounts], v.package + ":" + v.version
            )
            self.vulnIssueTotal += 1
            self.checkCallToAction(v)
            if v.severity == "high":
                self.manageDict(self.dictVulnIssues[self.iHigh], v.title)
                self.manageDict(
                    self.dictDepIssues[self.iDepByHighSev], v.package + ":" + v.version
                )
                self.vulnIssueCounts[self.iHigh] += 1
            elif v.severity == "medium":
                self.manageDict(self.dictVulnIssues[self.iMedium], v.title)
                self.vulnIssueCounts[self.iMedium] += 1
            elif v.severity == "low":
                self.manageDict(self.dictVulnIssues[self.iLow], v.title)
                self.vulnIssueCounts[self.iLow] += 1

            if v.cvssScore >= 9.0:
                self.manageDict(self.dictVulnIssues[self.iCritical], v.title)
                self.manageDict(
                    self.dictDepIssues[self.iDepByCriticalSev],
                    v.package + ":" + v.version,
                )
                self.vulnIssueCounts[self.iCritical] += 1

            curCVEList = v.identifiers["CVE"]
            for curCVE in curCVEList:
                if self.keyExists(self.cveWatchlist, curCVE):
                    self.manageDict(self.cveWatchlistFound, curCVE)
                    self.newsIssueTotal += 1

        for l in issueset.all().issues.licenses:
            self.licenseIssueTotal += 1
            if l.severity == "high":
                self.manageDict(self.dictLicenseIssues[self.iHigh], l.title)
                self.licenseIssueCounts[self.iHigh] += 1
            elif l.severity == "medium":
                self.manageDict(self.dictLicenseIssues[self.iMedium], l.title)
                self.licenseIssueCounts[self.iMedium] += 1
            elif l.severity == "low":
                self.manageDict(self.dictLicenseIssues[self.iLow], l.title)
                self.licenseIssueCounts[self.iLow] += 1


#####ANALYSIS
##GET NEXT TWO VALUES FROM COMMANDLINE
snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
client = SnykClient(snyk_token)
issueset = client.organizations.get(org_id).projects.get(project_id).issueset

masterlog = analysisLog("MASTER LOG", org_id + "/" + project_id)
masterlog.analyzeRepo(issueset)
masterlog.printResults()
