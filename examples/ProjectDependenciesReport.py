import json

from snyk import SnykClient


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


def list_of_dictionaries_to_map(input_list, key_field, data_fields_list=None):
    lookup_map = {}
    for next_item in input_list:
        next_item_key = next_item[key_field]
        data = {}
        if data_fields_list is None:
            # include all other fields in the data
            for k, v in next_item.items():
                if k != key_field:
                    data[k] = v
        lookup_map[next_item_key] = data
        print("added another")
    return lookup_map


def get_project_tree(snyk_token, org_id, project_id):
    client = SnykClient(snyk_token)
    res_dep_graph = client.organizations.get(org_id).projects.get(project_id).dependency_graph
    print(res_dep_graph)

    print("\nPackages (Flat List):")
    for pkg in res_dep_graph.pkgs:
        print("%s | %s" % (pkg.id, pkg.info))

    all_packages = res_dep_graph.pkgs

    print("\nGraph data:")
    graph = res_dep_graph.graph
    root_node_id = graph.rootNodeId
    nodes = graph.nodes

    for node in nodes:
        print("%s | %s" % (node.nodeId, node.pkgId))
        child_nodes = node.deps
        if len(child_nodes) > 0:
            for child_node in child_nodes:
                print("  - Child: %s" % child_node)
        print()

    # Convert the all_packages to a lookup map by package ID
    packages_lookup_map = {}
    for pkg in all_packages:
        print(pkg)
        package_id = pkg.id
        packages_lookup_map[package_id] = {
            "package_name": pkg.info.name,
            "package_version": pkg.info.version,
        }

    # Get licenses for all dependencies in the project
    lst_res_license = client.organizations.get(org_id).projects.get(project_id).dependencies.all()

    # make into a lookup table by package_id
    package_id_to_license_info_map = {}  # package_id -> { license info }
    for r in lst_res_license:
        package_id = r.id
        licenses = r.licenses
        package_id_to_license_info_map[package_id] = licenses

    print("\n\npackage_id_to_license_info_map:")
    print(package_id_to_license_info_map)

    # Get the license issues and then enhance package_id_to_license_info_map with the license classification or none
    issues = client.organizations.get(org_id).projects.get(project_id).issueset.all().issues
    license_issues_list = issues.licenses

    # map to lookup table
    license_issues_lookup_map = {license_issue.id: license_issue.severity for license_issue in license_issues_list}

    for pkgId, licensesList in package_id_to_license_info_map.items():
        for l in licensesList:
            license_id = l.id
            print(license_id)

            if license_id in license_issues_lookup_map:
                print("append additional info")
                severity = license_issues_lookup_map[license_id]
                l.severity = severity
            else:
                l.severity = "none"

            # lookup the license id in license_issues_lookup_map and see if there's an issue
            # add a 'classification' to the licenseInfo

    # Convert nodes to a dictionary by nodeId
    node_lookup_map = {}
    for node in nodes:
        node_id = node.nodeId
        package_id = node.pkgId
        node_lookup_map[node_id] = {
            "pkgId": node.pkgId,
            # TODO: Pull in the packages_name and package_version from packages_lookup_map
            "package_name": packages_lookup_map[package_id]["package_name"],
            "package_version": packages_lookup_map[package_id]["package_version"],
            "deps": node.deps,
        }

    print(node_lookup_map)
    root_node_package_id = node_lookup_map[root_node_id]["pkgId"]

    # Enhance node_lookup_map with license data from package_id_to_license_info_map
    for node_id in node_lookup_map.keys():
        if node_id == root_node_id:
            continue  # TODO: figure out how to get the project licenses
        print(node_id)

        # because if there's more than one node with the same package@version, it uses package@version|i to delinate them
        node_id_package_id = node_id.split("|")[0]
        licenses_info = package_id_to_license_info_map[node_id_package_id]
        node_lookup_map[node_id]["licenses"] = licenses_info

    # Now create a new structure based on node_lookup_map which is a deeply nested structure of the same data
    project_structured_tree = {}
    

    def get_node_to_append(node_id, base_path):  # might make sense to rename get_dependencies
        obj = node_lookup_map[node_id]
        pkgId = obj["pkgId"]
        print("node_id: %s" % pkgId)

        path = ""
        if not base_path:
            path = pkgId
        else:
            path = "%s > %s" % (base_path, pkgId)

        child_nodes = []
        for d in obj["deps"]:
            child_node_id = d["nodeId"]
            child_node = get_node_to_append(child_node_id, path)
            child_nodes.append(child_node)

        node_to_append = {
            "pkgId": pkgId,
            "package_name": obj["package_name"],
            "package_version": obj["package_version"],
            "path": path,
            "licenses": obj.get("licenses"),
            "dependencies": child_nodes,
        }

        return node_to_append

    # print(root_node_package_id)
    project_dependencies_structure = get_node_to_append(root_node_id, "")
    project_structured_tree = {"project": project_dependencies_structure}
    return project_structured_tree


def get_flat_dependencies(dep_list):
    flat_dep_list = []
    for d in dep_list:
        package_id = d["pkgId"]
        licences = d["licenses"]
        path = d["path"]

        simplified_liceses_list = [l["title"] for l in d["licenses"]]
        licenses_str = ", ".join(simplified_liceses_list)

        flat_dep_list.append(
            {"pkgId": package_id, "path": path, "licenses": licenses_str}
        )
        flat_child_deps_list = get_flat_dependencies(d["dependencies"])
        flat_dep_list.extend(flat_child_deps_list)
    return flat_dep_list
