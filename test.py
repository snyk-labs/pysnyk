import argparse

import xlsxwriter

from snyk import SnykClient
# COMMENTED OUT TO AVOID ENVIRONMENT DIFFERENCES:
# from utils import get_default_token_path, get_token




# MODIFIED WITH HARDCODED CREDS TO AVOID ENVIRONMENT DIFFERENCES
# snyk_token_path = get_default_token_path()
# snyk_token = get_token(snyk_token_path)
snyk_token = "e18706cc-31f8-4424-b732-7ea635094bd8"
org_id = "12772327-94dc-4e1a-b269-08938d529d9d"
tag_id = "8_4_0"


def output_excel(vulns, output_path):
    excel_workbook = xlsxwriter.Workbook(output_path)
    excel_worksheet = excel_workbook.add_worksheet()
    format_bold = excel_workbook.add_format({"bold": True})

    row_index = 0

    col_index = 0
    lst_col_headers = list(vulns[0].keys())

    for ch in lst_col_headers:
        excel_worksheet.write(
            row_index, col_index, lst_col_headers[col_index], format_bold
        )
        col_index += 1

    for v in vulns:
        row_index += 1

        col_index = 0
        for k in lst_col_headers:
            excel_worksheet.write(row_index, col_index, v[k])
            col_index += 1

    excel_workbook.close()


client = SnykClient(snyk_token)

myProjects = client.organizations.get(org_id).projects.filter(tags=[{"key": "version", "value": tag_id}])
for p in myProjects:
    print("\n\n %s" % p.name)
    if  p.name == 'CounterACT_8@rel/8.4.0':
        issue_set = p.issueset_aggregated.all().issues
    else:
        issue_set = p.issueset_aggregated.all().issues if 'vulnerabilities' in dir(p) else []

    #issue_set = p.vulnerabilities if 'vulnerabilities' in dir(p) else []
    lst_output = []

    for v in issue_set:
        """print("\n %s" % v.issueData.title)
        print("  id: %s" % v.issueData.id)
        print("  url: %s" % v.issueData.url)
        print("  Severity: %s" % v.issueData.severity)
        print("  CVSS Score: %s" % v.issueData.cvssScore)
    """
        print("HELLO")
        # for the excel output
        new_output_item = {
            "project": p.name,
            "title": v.issueData.title,
            "id": v.issueData.id,
            "url": v.issueData.url,
            "severity": v.issueData.severity,
            "cvssScore": v.issueData.cvssScore,
        }
        lst_output.append(new_output_item)

