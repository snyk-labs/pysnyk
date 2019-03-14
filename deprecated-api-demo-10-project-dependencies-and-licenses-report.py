import json
import argparse
import xlsxwriter
import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


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


# TODO: specify --orgId=<your-org-id> as a command line parameter or just manually set it here in the code
# TODO: specify --projectId=<your-org-id> as a command line parameter or just manually set it here in the code
args = parse_command_line_args()
org_id = args.orgId
project_id = args.projectId

json_res_dep_graph = SnykAPI.snyk_projects_get_product_dependency_graph(org_id, project_id)

print_json(json_res_dep_graph)


print('\nPackages (Flat List):')
for pkg in json_res_dep_graph['depGraph']['pkgs']:
    print('%s | %s' % (pkg['id'], pkg['info']))

all_packages = json_res_dep_graph['depGraph']['pkgs']


print('\nGraph data:')
graph = json_res_dep_graph['depGraph']['graph']
root_node_id = graph['rootNodeId']
nodes = graph['nodes']

for node in nodes:
    print('%s | %s' % (node['nodeId'], node['pkgId']))
    child_nodes = node['deps']
    if len(child_nodes) > 0:
        for child_node in child_nodes:
            print('  - Child: %s' % child_node)
    print()


# Convert the all_packages to a lookup map by package ID
packages_lookup_map = {}
for pkg in all_packages:
    print(pkg)
    package_id = pkg['id']
    packages_lookup_map[package_id] = {
        'package_name': pkg['info']['name'],
        'package_version': pkg['info']['version']
    }


# Get licenses for all dependencies in the project
lst_res_license = SnykAPI.snyk_dependencies_list_all_dependencies_by_project(org_id, project_id)

# make into a lookup table by package_id
licenses_lookup_map = {}
for r in lst_res_license:
    package_id = r['id']
    licenses = r['licenses']
    licenses_lookup_map[package_id] = licenses

print('\n\nlicenses_lookup_map:')
print_json(licenses_lookup_map)


# Convert nodes to a dictionary by nodeId
node_lookup_map = {}
for node in nodes:
    node_id = node['nodeId']
    package_id = node['pkgId']
    node_lookup_map[node_id] = {
        'pkgId': node['pkgId'],
        # TODO: Pull in the packages_name and package_version from packages_lookup_map
        'package_name': packages_lookup_map[package_id]['package_name'],
        'package_version': packages_lookup_map[package_id]['package_version'],
        'deps': node['deps']
    }

print(node_lookup_map)
root_node_package_id = node_lookup_map[root_node_id]['pkgId']


# Enhance node_lookup_map with license data from licenses_lookup_map
for node_id in node_lookup_map.keys():
    if node_id == root_node_id:
        continue  # TODO: figure out how to get the project licenses
    print(node_id)
    licenses_info = licenses_lookup_map[node_id]
    node_lookup_map[node_id]['licenses'] = licenses_info


# Now create a new structure based on node_lookup_map which is a deeply nested structure of the same data
project_structured_tree = {}


def get_node_to_append(node_id, base_path):  # might make sense to rename get_dependencies
    obj = node_lookup_map[node_id]
    pkgId = obj['pkgId']
    print('node_id: %s' % pkgId)

    path = ''
    if not base_path:
        path = pkgId
    else:
        path = '%s > %s' % (base_path, pkgId)

    child_nodes = []
    for d in obj['deps']:
        child_node_id = d['nodeId']
        child_node = get_node_to_append(child_node_id, path)
        child_nodes.append(child_node)

    node_to_append = {
        'pkgId': pkgId,
        'package_name': obj['package_name'],
        'package_version': obj['package_version'],
        'path': path,
        'licenses': obj.get('licenses'),
        'dependencies': child_nodes
    }

    return node_to_append


# print(root_node_package_id)
project_dependencies_structure = get_node_to_append(root_node_id, '')
project_structured_tree = {
    'project': project_dependencies_structure
}


def get_flat_dependencies(dep_list):
    flat_dep_list = []
    for d in dep_list:
        package_id = d['pkgId']
        licences = d['licenses']
        path = d['path']

        simplified_liceses_list = [l['title'] for l in d['licenses']]
        licenses_str = ', '.join(simplified_liceses_list)

        flat_dep_list.append({
            'pkgId': package_id,
            'path': path,
            'licenses': licenses_str,

        })
        flat_child_deps_list = get_flat_dependencies(d['dependencies'])
        flat_dep_list.extend(flat_child_deps_list)
    return flat_dep_list


# Results
#########

# Results - show flattened list
print('\n\n')
flattened_dependencies_list = get_flat_dependencies(project_structured_tree['project']['dependencies'])
for next_dep in flattened_dependencies_list:
    print('%s   %s  %s' % (next_dep['pkgId'], next_dep['licenses'], next_dep['path']))


# Results - create cvs output file
output_file = 'output/api-demo-10-output.csv'
with open(output_file, 'w') as output_csv:
    for next_dep in flattened_dependencies_list:
        str_csv_line = '%s  %s  %s' % (next_dep['pkgId'], next_dep['licenses'], next_dep['path'])  # using tab delimitation because I used ',' for the licenses
        output_csv.write('%s\n' % str_csv_line)


# Results - write as Excel file
output_file_name_xlsx = 'output/api-demo-10-output.xlsx'
excel_workbook = xlsxwriter.Workbook(output_file_name_xlsx)
excel_worksheet = excel_workbook.add_worksheet()

row_index = 0
for next_dep in flattened_dependencies_list:
    str_csv_line = '%s  %s  %s' % (next_dep['pkgId'], next_dep['licenses'],
                                   next_dep['path'])  # using tab delimitation because I used ',' for the licenses

    excel_worksheet.write(row_index, 0, next_dep['pkgId'])
    excel_worksheet.write(row_index, 1, next_dep['licenses'])
    excel_worksheet.write(row_index, 2, next_dep['path'])
    row_index += 1

excel_workbook.close()

print('\n\n done')

