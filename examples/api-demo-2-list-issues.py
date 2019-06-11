import argparse
import xlsxwriter

from snyk import SnykClient
from utils import get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument('--orgId', type=str,
                        help='The Snyk Organisation Id', required=True)

    parser.add_argument('--projectId', type=str,
                        help='The project ID in Snyk', required=True)

    parser.add_argument('--outputPathExcel', type=str,
                        help='Optional. The desired output if you want Excel output (use .xlsx).')

    args = parser.parse_args()

    return args


snyk_token = get_token('snyk-api-token')
args = parse_command_line_args()
org_id = args.orgId
project_id = args.projectId


def output_excel(vulns, output_path):
    excel_workbook = xlsxwriter.Workbook(output_path)
    excel_worksheet = excel_workbook.add_worksheet()
    format_bold = excel_workbook.add_format({'bold': True})

    row_index = 0

    col_index = 0
    lst_col_headers = list(vulns[0].keys())

    for ch in lst_col_headers:
        excel_worksheet.write(row_index, col_index, lst_col_headers[col_index], format_bold)
        col_index += 1

    for v in vulns:
        row_index += 1

        col_index = 0
        for k in lst_col_headers:
            excel_worksheet.write(row_index, col_index, v[k])
            col_index += 1

    excel_workbook.close()


# List issues in a project
client = SnykClient(token=snyk_token)
json_res = client.snyk_projects_project_issues(org_id, project_id)
print(json_res)

vulnerability_issues = json_res['issues']['vulnerabilities']
lst_output = []
for v in vulnerability_issues:
    print('\n %s' %v['title'])
    print('  id: %s' % v['id'])
    print('  url: %s' % v['url'])

    print('  %s@%s' % (v['package'], v['version']))
    print('  Severity: %s' % v['severity'])
    print('  CVSS Score: %s' % v['cvssScore'])

    proximity = len(v['from'])
    path_str = '>'.join(v['from'])

    print('  proximety: %s' % proximity)
    print('  path: %s' % path_str)

    # for the excel output
    new_output_item = {
        'title': v['title'],
        'id': v['id'],
        'url': v['url'],

        'package': '%s@%s' % (v['package'], v['version']),
        'severity': v['severity'],
        'cvssScore': v['cvssScore'],

        'proximity': proximity,
        'path': path_str
    }

    lst_output.append(new_output_item)

if args.outputPathExcel:
    output_excel(lst_output, args.outputPathExcel)


