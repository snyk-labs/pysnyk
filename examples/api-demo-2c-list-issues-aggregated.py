import argparse

import xlsxwriter

from snyk import SnykClient
from utils import get_default_token_path, get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation Id", required=True
    )
    parser.add_argument(
        "--projectId", type=str, help="The project ID in Snyk", required=True
    )
    parser.add_argument(
        "--outputPathExcel",
        type=str,
        help="Optional. The desired output if you want Excel output (use .xlsx).",
    )
    return parser.parse_args()


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId
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
issue_set = client.organizations.get(org_id).projects.get(project_id).issueset_aggregated.all()

lst_output = []
for v in issue_set.issues:
    print("\n %s" % v.issueData.title)
    print("  id: %s" % v.id)
    print("  url: %s" % v.issueData.url)

    print("  %s@%s" % (v.pkgName, v.pkgVersions))
    print("  Severity: %s" % v.issueData.severity)
    print("  CVSS Score: %s" % v.issueData.cvssScore)

    # for the excel output
    new_output_item = {
        "title": v.issueData.title,
        "id": v.id,
        "url": v.issueData.url,
        "package": "%s@%s" % (v.pkgName, v.pkgVersions),
        "severity": v.issueData.severity,
        "cvssScore": v.issueData.cvssScore,
    }
    lst_output.append(new_output_item)

if args.outputPathExcel:
    output_excel(lst_output, args.outputPathExcel)
