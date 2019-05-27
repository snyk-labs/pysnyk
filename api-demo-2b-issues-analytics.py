import json

import SnykAPI
###SAMPLE RUN COMMAND: python3 api-demo-2b-issues-analytics.py
## make sure to install pathlib, requests, json
##Update org_id and my_js_goof_project_id

def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


org_id = 'shawn-0lj'
my_js_goof_project_id = 'goof'


# List issues in a project
json_res = SnykAPI.snyk_projects_project_issues(org_id, my_js_goof_project_id)
#print(json_res)
#for v in json_res['issues']['vulnerabilities']:
#    print('\n %s' %v['title'])
#    print('  %s@%s' % (v['package'], v['version']))
#    print('  Severity: %s' % v['severity'])

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
            print('Issue: ' + key + ' , Value:' + str(dict[key]))
        else:
            print('Issue: ' + key + ' , Value:' + dict[key]) 
    if(len(dict)==0):
        print('None found')

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

manageDictVulnCritical={}
manageDictVulnHigh={}
manageDictVulnMedium={}
manageDictVulnLow={}

manageDictLicenseHigh={}
manageDictLicenseMedium={}
manageDictLicenseLow={}

cveWatchlist = {'CVE-2018-1000851'}
cveWatchlistFound={}
###Goal 1 - get counts
for v in json_res['issues']['vulnerabilities']:
    if(v['severity']=='high'):
        manageDictVulnHigh=manageDict(manageDictVulnHigh, v['title'])
        countVulnHigh+=1
    elif(v['severity']=='medium'):
        manageDictVulnMedium=manageDict(manageDictVulnMedium, v['title'])
        countVulnMedium+=1
    elif(v['severity']=='low'):
        manageDictVulnLow=manageDict(manageDictVulnLow, v['title'])
        countVulnLow+=1

    if(v['cvssScore'] >= 9.0):
        manageDictVulnCritical=manageDict(manageDictVulnCritical, v['title'])
        countVulnCritical+=1
    
    curCVEList = v['identifiers']['CVE']
    for curCVE in curCVEList:
        if(keyExists(cveWatchlist,curCVE)):
            print('CVE Watchlist item found: ' + curCVE)
            cveWatchlistFound=manageDict(cveWatchlistFound, curCVE)

for l in json_res['issues']['licenses']:
    if(l['severity']=='high'):
        manageDictLicenseHigh=manageDict(manageDictLicenseHigh, l['title'])
        countLicenseHigh+=1
    elif(l['severity']=='medium'):
        manageDictLicenseMedium=manageDict(manageDictLicenseMedium, l['title'])
        countLicenseMedium+=1
    elif(l['severity']=='low'):
        manageDictLicenseLow=manageDict(manageDictLicenseLow, l['title'])
        countLicenseLow+=1


####OUTPUT

print('\n\n****Vulnerability Issues***')
print('\nCritical Severity: ' + str(countVulnCritical) + ',High Severity: ' + str(countVulnHigh) + ', Medium Severity: ' + str(countVulnMedium) + ', Low Severity: ' + str(countVulnLow) )
#print('Critical vulns counter:' + str(countVulnCritical))
printDict('\n\nCritical Vulnerabilities: ' , manageDictVulnCritical,True)
printDict('\nHigh Vulnerabilities: ' , manageDictVulnHigh,True)
printDict('\nMedium Vulnerabilities: ' , manageDictVulnMedium,True)
printDict('\nLow Vulnerabilities: ' , manageDictVulnLow,True)

print('\n\n****License Issues***')
print('\nHigh Severity: ' + str(countLicenseHigh) + ', Medium Severity: ' + str(countLicenseMedium) + ', Low Severity: ' + str(countLicenseLow))
printDict('\nHigh Severity Licenses Issues: ' , manageDictLicenseHigh,True)
printDict('\nMedium Severity Licenses Issues: ' , manageDictLicenseMedium,True)
printDict('\nLow Severity Licenses Issues: ' , manageDictLicenseLow,True)

print('\n\n****CVE Watchlist***')
print('The following issues are currently critical vulnerabilities that have made the news and were found to be in your codebase')    
printDict('', cveWatchlistFound,True)