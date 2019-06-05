import json

import SnykAPI
###SAMPLE RUN COMMAND: python3 api-demo-2b-issues-analytics.py
## make sure to install pathlib, requests, json
##Update org_id and my_js_goof_project_id

def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


org_id = ''
my_js_goof_project_id = ''


# List issues in a project
json_res = SnykAPI.snyk_projects_project_issues(org_id, my_js_goof_project_id)
print(json.dumps(json_res,indent=2))

def manageDict(dict, key): 
    if keyExists(dict, key): 
        dict[key] +=1 
    else: 
        dict[key] = 1
    return dict

def keyExists(dict, key):
    if key in dict: 
        return True 
    else: 
        return False

def printDict(title, dict,isNumber):
    if(title != ''):
        print(title)
    for key in dict: 
        if(isNumber == True):
            print('\t\tIssue: ' + key + ' , Value:' + str(dict[key]))
        else:
            print('\t\tIssue: ' + key + ' , Value:' + dict[key]) 
    if(len(dict)==0):
        print('\t\tNone found')

########
# ANALYTIC GOAL 1
# 1) MOST PREVALENT ISSUES by severity
# 2) ISSUE COUNTS
# 3) Criticals (CVSS 9.0 and above)
#ANALYTIC GOAL 2
# 1) Look for issues recently in news, i.e. event-stream to flag relevant issues
#########
countVulnCritical=0
countVulnHigh=0
countVulnMedium=0
countVulnLow=0

countLicenseHigh=0
countLicenseMedium=0
countLicenseLow=0

dictVulnCritical={}
dictVulnHigh={}
dictVulnMedium={}
dictVulnLow={}

dictLicenseHigh={}
dictLicenseMedium={}
dictLicenseLow={}

cveWatchlist = {'CVE-2018-1000851'} #currently just eventstream
cveWatchlistFound={}
###Goal 1 - get counts
for v in json_res['issues']['vulnerabilities']:
    if(v['severity']=='high'):
        manageDict(dictVulnHigh, v['title'])
        countVulnHigh+=1
    elif(v['severity']=='medium'):
        manageDict(dictVulnMedium, v['title'])
        countVulnMedium+=1
    elif(v['severity']=='low'):
        manageDict(dictVulnLow, v['title'])
        countVulnLow+=1

    if(v['cvssScore'] >= 9.0):
        manageDict(dictVulnCritical, v['title'])
        countVulnCritical+=1
    
    curCVEList = v['identifiers']['CVE']
    for curCVE in curCVEList:
        if(keyExists(cveWatchlist,curCVE)):
            #print('CVE Watchlist item found: ' + curCVE)
            manageDict(cveWatchlistFound, curCVE)

for l in json_res['issues']['licenses']:
    if(l['severity']=='high'):
        manageDict(dictLicenseHigh, l['title'])
        countLicenseHigh+=1
    elif(l['severity']=='medium'):
        manageDict(dictLicenseMedium, l['title'])
        countLicenseMedium+=1
    elif(l['severity']=='low'):
        manageDict(dictLicenseLow, l['title'])
        countLicenseLow+=1


####OUTPUT

print('\n\n****Vulnerability Issues***')
print('\nCritical Severity: ' + str(countVulnCritical) + ',High Severity: ' + str(countVulnHigh) + ', Medium Severity: ' + str(countVulnMedium) + ', Low Severity: ' + str(countVulnLow) )
#print('Critical vulns counter:' + str(countVulnCritical))
printDict('\n\n\tCritical Vulnerabilities: ' , dictVulnCritical,True)
printDict('\n\tHigh Vulnerabilities: ' , dictVulnHigh,True)
printDict('\n\tMedium Vulnerabilities: ' , dictVulnMedium,True)
printDict('\n\tLow Vulnerabilities: ' , dictVulnLow,True)

print('\n\n****License Issues***')
print('\n\tHigh Severity: ' + str(countLicenseHigh) + ', Medium Severity: ' + str(countLicenseMedium) + ', Low Severity: ' + str(countLicenseLow))
printDict('\n\tHigh Severity Licenses Issues: ' , dictLicenseHigh,True)
printDict('\n\tMedium Severity Licenses Issues: ' , dictLicenseMedium,True)
printDict('\n\tLow Severity Licenses Issues: ' , dictLicenseLow,True)

print('\n\n****CVE Watchlist***')
print('The following issues are currently critical vulnerabilities that have made the news and were found to be in your codebase')    
printDict('\t', cveWatchlistFound,True)

###We should make the script output to a spreadsheet. From there to generate PDF
##NOTE THIS WILL GET LIST OF REPOS: https://api.github.com/users/$GHUSER/repos?per_page=100
##this way we can get list of repos from the github API, then run the CLI like: snyk test https://github.com/ghuser/reponame
##assuming outbrain is given as a parameter

##ADDITIONAL TASK - when calculating severities, you have to match vulnerable module to vuln, maybe use  request:!:REDOS as format?
