import json
import collections
import SnykAPI
import operator
import argparse
from collections import OrderedDict
###SAMPLE RUN COMMAND: python3 api-demo-2b-issues-analytics.py --orgID=YOURORGIDHERE --projectID=YOURSNYKPROJECTID

org_id = ''
project_id = ''
json_rslts_repo = ''

def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument('--orgId', type=str,
                        help='The Snyk Organisation Id')

    parser.add_argument('--projectId', type=str,
                        help='The project ID in Snyk')

    args = parser.parse_args()

    if args.orgId is None:
        parser.error('You must specify --orgId')

    if args.projectId is None:
        parser.error('You must specify --projectId')

    return args


args = parse_command_line_args()
org_id = args.orgId
project_id = args.projectId

###START CLASS
class analysisLog:
    iCritical=0
    iHigh=1
    iMedium=2
    iLow=3
    arrSevDescriptions=['Critical (CVSS 9.0 and Above)', 'High','Medium','Low']
    #special convention for deps
    iDepByCriticalSev=0
    iDepByHighSev=1
    iDepIssueCounts=2
    sDepDescriptions=['By Number of Critical Severity Issues', 'By High Severity Issues', 'By Total Issue Count']

    def __init__(self, analysisObjID,reponame):
        #license and issue management
        self.id = analysisObjID
        self.reponame = reponame
        self.vulnIssueCounts = [0,0,0,0]
        self.licenseIssueCounts = [0,0,0,0]
        self.dictVulnIssues = [{},{},{},{}]
        self.dictLicenseIssues = [{},{},{},{}]

        #special convention for deps
        self.dictDepIssues = [{},{},{}] #dictDepCritical,dictDepHigh,dictDepIssueCount

        ###DICTIONAIRY OF NEWS WORTHY ATTACKS####
        #Searchlist
        self.cveWatchlist = {}
        #Description for printing - (ToDo: Read from file later)
        self.cveWatchlist['CVE-2018-1000851'] = 'Copay Bitcoin attack via Event-Stream'
        self.cveWatchlist['CVE-2017-5638'] = 'Equifax vulnerability via Struts'
        self.cveWatchlist['CVE-2018-1002204'] = 'Zip Slip - Found by Snyk!'
        
        ########################################
        self.cveWatchlistFound={}

    #Utilities
    def manageDict(self,dict, key): 
        if self.keyExists(dict, key): 
            dict[key] +=1 
        else: 
            dict[key] = 1
        return dict

    def keyExists(self,dict, key):
        if key in dict: 
            return True 
        else: 
            return False

    def printDict(self,title, dict,isNumber):
        if(title != ''):
            print(title)
        for key in dict: 
            if(isNumber == True):
                print('\t\tIssue: ' + key + ' , Count:' + str(dict[key]))
            else:
                print('\t\tIssue: ' + key + ' , Count:' + dict[key]) 
        if(len(dict)==0):
            print('\t\tNone found')

    def printDictWithDescriptDict(self,title, dictItems,dictDescription):
        if(title != ''):
            print(title)
        for key in dictItems: 
            print('\t\t' + key + ' , ' + dictDescription[key] + ', Count: ' + str(dictItems[key])) 
        if(len(dictItems)==0):
            print('\t\tNone found')

    def printTopDict(self,title, dict,isNumber,limiter):
        counter=0
        if(title != ''):
            print(title)
        for key in dict: 
            counter+=1
            if(counter>limiter):
                break
            if(isNumber == True):
                print('\t\tIssue: ' + key + ' , Count:' + str(dict[key]))
            else:
                print('\t\tIssue: ' + key + ' , Count:' + dict[key]) 
        if(len(dict)==0):
            print('\t\tNone found')

    def sortDict(self,dict):
        #sDict = sorted(dict.items(), key=operator.itemgetter(1))
        sDictOrdered = OrderedDict(sorted(dict.items(), key=lambda x: x[1],reverse=True))
        return sDictOrdered
    
    ##OUTPUT FUNCTIONS
    def printResultVulns(self):
        print('\nVULNERABILITY ANALYSIS')
        totalCount = self.vulnIssueCounts[self.iHigh] + self.vulnIssueCounts[self.iMedium] + self.vulnIssueCounts[self.iLow]
        print('\n\t\tTotal Count (High, Medium, Low): ' + str(totalCount) + ' , Calculated Critical Severity (CVSS 9.0 and above): ' + str(self.vulnIssueCounts[self.iCritical]) + ', High Severity: ' + str(self.vulnIssueCounts[self.iHigh]) + ', Medium Severity: ' + str(self.vulnIssueCounts[self.iMedium]) + ', Low Severity: ' + str(self.vulnIssueCounts[self.iLow]))
        
        for iSev in range( 0 ,4) :            
            self.printTopDict('\n\t' + self.arrSevDescriptions[iSev] + ' Severity Issues: ' , self.sortDict(self.dictVulnIssues[iSev]),True,5)
        
    def printResultLicense(self):
        print('\nLICENSE ANALYSIS')
        print('\n\tHigh Severity: ' + str(self.licenseIssueCounts[self.iHigh]) + ', Medium Severity: ' + str(self.licenseIssueCounts[self.iMedium]) + ', Low Severity: ' + str(self.licenseIssueCounts[self.iLow]))
        for iSev in range(1,4) :
            self.printTopDict('\n\t' + self.arrSevDescriptions[iSev] + ' Severity Issues: ' , self.sortDict(self.dictLicenseIssues[iSev]),True,5)

    def printResultDependency(self):
        print('\nDEPENDENCY ANALYSIS')
        print('The following lists are identifying what dependencies are problematic by having critical vulns, the most high severity or the most overall count of issues (because even medium/low have value)')
        for iDepIssueType in range(0,3) :
            self.printTopDict('\n\tDependency by ' + self.sDepDescriptions[iDepIssueType] + ': ' , self.sortDict(self.dictDepIssues[iDepIssueType]),True,5)

    def printNewsIssues(self):
        print('\n\n****CVE Watchlist***')
        print('The following issues are currently critical vulnerabilities that have made the news and were found to be in your codebase')    
        self.printDictWithDescriptDict('',self.cveWatchlistFound,self.cveWatchlist)
    
    def printResults(self):
            print('Analysis')
            print('\tID:' + self.id)
            if(self.reponame != ''):
                print('\tRepo/Project: ' + self.reponame)
            print('\n\nThe following analysis lists top 5 items in each area of analysis. Calculation was performed without grouping of vulnerabilities, highlighting every path to each vulnerability')
            self.printResultVulns()
            self.printResultLicense()
            self.printResultDependency()
            self.printNewsIssues()
            print('\n\n***END ANALYSIS***')
   
    #Analysis worker
    def analyzeRepo(self,json_res):
        ###Goal 1 - get counts
        for v in json_res['issues']['vulnerabilities']:
            self.manageDict(self.dictDepIssues[self.iDepIssueCounts], v['package'] + ':' + v['version'])
            if(v['severity']=='high'):
                self.manageDict(self.dictVulnIssues[self.iHigh], v['title'])
                self.manageDict(self.dictDepIssues[self.iDepByHighSev], v['package'] + ':' + v['version'])
                self.vulnIssueCounts[self.iHigh]+=1
            elif(v['severity']=='medium'):
                self.manageDict(self.dictVulnIssues[self.iMedium], v['title'])
                self.vulnIssueCounts[self.iMedium]+=1
            elif(v['severity']=='low'):
                self.manageDict(self.dictVulnIssues[self.iLow], v['title'])
                self.vulnIssueCounts[self.iLow]+=1

            if(v['cvssScore'] >= 9.0):
                self.manageDict(self.dictVulnIssues[self.iCritical], v['title'])
                self.manageDict(self.dictDepIssues[self.iDepByCriticalSev], v['package'] + ':' + v['version'])
                self.vulnIssueCounts[self.iCritical]+=1
        
            curCVEList = v['identifiers']['CVE']
            for curCVE in curCVEList:
                if(self.keyExists(self.cveWatchlist,curCVE)):
                    self.manageDict(self.cveWatchlistFound, curCVE)

        for l in json_res['issues']['licenses']:
            if(l['severity']=='high'):
                self.manageDict(self.dictLicenseIssues[self.iHigh], l['title'])
                self.licenseIssueCounts[self.iHigh]+=1
            elif(l['severity']=='medium'):
                self.manageDict(self.dictLicenseIssues[self.iMedium], l['title'])
                self.licenseIssueCounts[self.iMedium]+=1
            elif(l['severity']=='low'):
                self.manageDict(self.dictLicenseIssues[self.iLow], l['title'])
                self.licenseIssueCounts[self.iLow]+=1

#####ANALYSIS
##GET NEXT TWO VALUES FROM COMMANDLINE
json_rslts_repo = SnykAPI.snyk_projects_project_issues(org_id, project_id)
#print(json.dumps(json_res,indent=2))

masterlog = analysisLog('MASTER LOG', org_id + '/' + project_id)
masterlog.analyzeRepo(json_rslts_repo)
masterlog.printResults()
