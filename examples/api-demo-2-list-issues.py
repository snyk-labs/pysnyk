***REMOVED***
import xlsxwriter

***REMOVED***
from utils import get_token


***REMOVED***
***REMOVED***
***REMOVED***
        "--orgId", type=str, help="The Snyk Organisation Id", required=True
***REMOVED***
***REMOVED***
        "--projectId", type=str, help="The project ID in Snyk", required=True
***REMOVED***
***REMOVED***
        "--outputPathExcel",
        type=str,
        help="Optional. The desired output if you want Excel output (use .xlsx).",
***REMOVED***
***REMOVED***


snyk_token = get_token("snyk-api-token")
***REMOVED***
***REMOVED***
project_id = args.projectId


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
    ***REMOVED***
        col_index += 1

    for v in vulns:
        row_index += 1

        col_index = 0
        for k in lst_col_headers:
            excel_worksheet.write(row_index, col_index, v[k])
            col_index += 1

    excel_workbook.close()


client = SnykClient(snyk_token)
issue_set = client.organizations.get(org_id).projects.get(project_id).issues()

lst_output = []
for v in issue_set.issues.vulnerabilities:
    print("\n %s" % v.title)
    print("  id: %s" % v.id)
    print("  url: %s" % v.url)

    print("  %s@%s" % (v.package, v.version))
    print("  Severity: %s" % v.severity)
    print("  CVSS Score: %s" % v.cvssScore)

    # for the excel output
    new_output_item = {
        "title": v.title,
        "id": v.id,
        "url": v.url,
        "package": "%s@%s" % (v.package, v.version),
        "severity": v.severity,
        "cvssScore": v.cvssScore,
    }
    lst_output.append(new_output_item)

if args.outputPathExcel:
    output_excel(lst_output, args.outputPathExcel)
