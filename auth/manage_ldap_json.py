from __future__ import print_function, unicode_literals
import json
import argparse
import ldap3
from tabulate import tabulate
import sys
import os
import socket

# needed for python 2 and 3 compabilility to check str types
try:
    # python 2 case
    basestring
except NameError:
    # python 3 case
    basestring = str

# needed for python 2 and 3 compabilility to get user input
try:
    # python 2 case
    input = raw_input
except NameError:
    # python 3 case
    pass


def verify(args):
    if args.surpress_verify_output:
        sys.stdout = open(os.devnull, "w")

    try:
        with open(args.file, "r") as f:
            config_json = json.load(f)

        print("Valid JSON")

        # Now need to check that it's valid config on top of being valid JSON
        if "server" not in config_json:
            print("Server not specified")
            return 1

        # check if server given can be contacted
        # ignore blank in case the config doesn't need a server
        if config_json["server"]:
            try:
                s = ldap3.Server(config_json["server"])
                conn = ldap3.Connection(s, auto_bind=True)
                conn.unbind()
            except ldap3.core.exceptions.LDAPSocketOpenError:
                print("Cannot connect to LDAP server - is the address correct?")
                return 1

        if "endpoints" not in config_json:
            print("No endpoints are specified")
            return 1

        if not isinstance(config_json["endpoints"], list):
            print("Endpoints should be a list")
            return 1

        for index, endpoint in enumerate(config_json["endpoints"]):
            if not isinstance(endpoint, dict):
                print("Endpoints should be a list of objects, endpoint list index " + str(index) + " is not an object")
                return 1

            if "endpoint_path" not in endpoint:
                print("No endpoint path specified for endpoint list index " + str(index))
                return 1

            if not isinstance(endpoint["endpoint_path"], basestring):
                print(str(endpoint["endpoint_path"]) + " is not a string, endpoint_path should be a string for endpoint list index " + str(index))
                return 1

            # TODO: bother regexing the endpoint path?

            if "allowed_ip_addresses" not in endpoint:
                print("No allowed ip addresses specified for endpoint list index " + str(index))
                return 1

            if not isinstance(endpoint["allowed_ip_addresses"], list):
                print(str(endpoint["allowed_ip_addresses"]) + " is not a list, allowed_ip_addresses should be a list for endpoint list index " + str(index))
                return 1

            for ip_index, allowed_ip_address in enumerate(endpoint["allowed_ip_addresses"]):
                if not isinstance(allowed_ip_address, dict):
                    print("allowed_ip_addresses should be a list of objects, allowed_ip_addresses list index " + str(ip_index) + " endpoint list index " + str(index) + " has an allowed_ip_addresses list item that is not an object")
                    return 1

                if "ip" not in allowed_ip_address:
                    print("No ip specified in allowed_ip_addresses list index " + str(ip_index) + " endpoint list index " + str(index))
                    return 1

                if "permissions" not in allowed_ip_address:
                    print("No permissions specified in allowed_ip_addresses list index " + str(ip_index) + " endpoint list index " + str(index))
                    return 1

                if not isinstance(allowed_ip_address["ip"], basestring):
                    print("allowed_ip_address ip should be a string, in allowed_ip_addresses list index " + str(ip_index) + " endpoint list index " + str(index))
                    return 1

                # use sets to check that only r, l, w and d values are allowed, it does allow for empty permissions
                if not set(allowed_ip_address["permissions"]) <= set([u"r", u"w", u"l", u"d"]):
                    print("allowed_ip_address permissions should be a string containing any of the modes r (read) l (list) w (write) d (delete), in allowed_ip_address list index " + str(ip_index) + " endpoint list index " + str(index))
                    return 1

            if "propogate_permissions" in endpoint and not isinstance(endpoint["propogate_permissions"], bool):
                print(str(endpoint["propogate_permissions"]) + " is not a bool, propogate_permissions should be a bool for endpoint list index " + str(index))
                return 1

            if "allowed_attributes" not in endpoint:
                print("No allowed attributes specified for endpoint list index " + str(index))
                return 1

            if not isinstance(endpoint["allowed_attributes"], list):
                print(str(endpoint["allowed_attributes"]) + " is not a list, allowed_attributes should be a list for endpoint list index " + str(index))
                return 1

            for attr_index, allowed_attributes in enumerate(endpoint["allowed_attributes"]):
                if not isinstance(allowed_attributes, dict):
                    print("allowed_attributes should be a list of objects, attribute_requirements list index " + str(attr_index) + " endpoint list index " + str(index) + " has an allowed_attributes list item that is not an object")
                    return 1

                if "attribute_requirements" not in allowed_attributes:
                    print("No attribute_requirements specified in attribute_requirements list index " + str(attr_index) + " endpoint list index " + str(index))
                    return 1

                if "permissions" not in allowed_attributes:
                    print("No permissions specified in attribute_requirements list index " + str(attr_index) + " endpoint list index " + str(index))
                    return 1

                if not isinstance(allowed_attributes["attribute_requirements"], list):
                    print("attribute_requirements should be a list, in attribute_requirements list index " + str(attr_index) + " endpoint list index " + str(index))
                    return 1

                # use sets to check that only r, l, w and d values are allowed, it does allow for empty permissions
                if not set(allowed_attributes["permissions"]) <= set([u"r", u"w", u"l", u"d"]):
                    print("attribute_requirements permissions should be a string containing any of the modes r (read) l (list) w (write) d (delete), in attribute_requirements list index " + str(attr_index) + " endpoint list index " + str(index))
                    return 1

                for attr_req_index, attribute_requirements in enumerate(allowed_attributes["attribute_requirements"]):
                    if not isinstance(attribute_requirements, dict):
                        print("attribute_requirements should be a list of objects, attribute_requirements list index " + str(attr_index) + " endpoint list index " + str(index) + " has an attribute_requirements list item that is not an object")
                        return 1

                    if "attribute" not in attribute_requirements:
                        print("attribute_requirements items should have an attribute, attribute_requirements list index " + str(attr_index) + " endpoint list index " + str(index))
                        return 1

                    if not isinstance(attribute_requirements["attribute"], basestring):
                        print("attribute should be a string, attribute_requirements list index " + str(attr_index) + " endpoint list index " + str(index))
                        return 1

                    if "value" not in attribute_requirements:
                        print("attribute_requirements items should have a value, attribute_requirements list index " + str(attr_index) + " endpoint list index " + str(index))
                        return 1

        print("Config file is valid")
        # restore stdout
        sys.stdout = sys.__stdout__
        return 0

    except ValueError:
        print("Invalid JSON")


def list_endpoints(args):
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug the config file")
        return 1


    with open(args.file, "r") as f:
        config_json = json.load(f)

    for endpoint in config_json["endpoints"]:
        print(endpoint["endpoint_path"])

    return 0


def pretty_print_endpoint(endpoint):
    print("Endpoint path: " + endpoint["endpoint_path"] + "\n")
    if "propogate_permissions" in endpoint:
        print("Propogate permissions: " + str(endpoint["propogate_permissions"]))
    else:
        print("Propogate permissions: True")

    print("\nAllowed ips")
    ip_table = {"r": [], "l": [], "w": [], "d": []}
    for ip in endpoint["allowed_ip_addresses"]:
        if "r" in ip["permissions"]:
            ip_table["r"].append(ip["ip"])
        if "l" in ip["permissions"]:
            ip_table["l"].append(ip["ip"])
        if "w" in ip["permissions"]:
            ip_table["w"].append(ip["ip"])
        if "d" in ip["permissions"]:
            ip_table["d"].append(ip["ip"])

    print(tabulate(ip_table, headers=["read", "list", "write", "delete"]))
    print("\nAllowed Attributes")
    attribute_table = {"r": [], "l": [], "w": [], "d": []}
    for allowed_attributes in endpoint["allowed_attributes"]:
        # empty attribute list means we let anything have those permissions
        attribute_str = "Anything"
        for attribute in allowed_attributes["attribute_requirements"]:
            if attribute_str == "Anything":
                attribute_str = attribute["attribute"] + " = " + attribute["value"]
            else:
                attribute_str = attribute_str + " AND " + attribute["attribute"] + " = " + attribute["value"]

        if "r" in allowed_attributes["permissions"]:
            if len(attribute_table["r"]) != 0:
                attribute_table["r"].append(" OR " + attribute_str)
            else:
                attribute_table["r"].append(attribute_str)
        if "l" in allowed_attributes["permissions"]:
            if len(attribute_table["l"]) != 0:
                attribute_table["l"].append(" OR " + attribute_str)
            else:
                attribute_table["l"].append(attribute_str)
        if "w" in allowed_attributes["permissions"]:
            if len(attribute_table["w"]) != 0:
                attribute_table["w"].append(" OR " + attribute_str)
            else:
                attribute_table["w"].append(attribute_str)
        if "d" in allowed_attributes["permissions"]:
            if len(attribute_table["d"]) != 0:
                attribute_table["d"].append(" OR " + attribute_str)
            else:
                attribute_table["d"].append(attribute_str)

    print(tabulate(attribute_table, headers=["read", "list", "write", "delete"]))
    return 0


def endpoint_info(args):
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug the config file")
        return 1

    with open(args.file, "r") as f:
        config_json = json.load(f)

    for endpoint in config_json["endpoints"]:
        if endpoint["endpoint_path"] == args.endpoint_path:
            # can just print JSON, or try and tidy the data up a bit
            if args.json:
                print(json.dumps(endpoint, indent=4))
            else:
                pretty_print_endpoint(endpoint)

            return 0


def prompt_bool(message):
    while True:
        prompt = input(message).lower()
        true_values = {"t", "true", "y", "yes", "ok"}
        false_values = {"f", "false", "n", "no"}
        if prompt in true_values:
            return True
        elif prompt in false_values:
            return False
        else:
            print("Invalid input, please enter a yes or no response")


def add_endpoint(args):
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug the config file")
        return 1

    with open(args.file, "r") as f:
        config_json = json.load(f)

    # need to create an endpoint entry by querying the user
    new_endpoint = {
        "endpoint_path": args.endpoint_path,
        "allowed_attributes": [],
        "allowed_ip_addresses": []
    }

    print("Creating config for endpoint " + args.endpoint_path + "\n")

    propogate_permissions = prompt_bool("Should the permissions specified for this path be applied to any of it's children/subfolders not specified in this file? (Y/n) ")
    new_endpoint["propogate_permissions"] = propogate_permissions

    # query loop for ip address permissions
    process_ips = prompt_bool("Would you like to specify permissions for specific IP addresses? (Y/n) ")
    while process_ips:
        while True:
            ip = input("Enter ip address: ")
            # TODO ipv6?
            try:
                socket.inet_aton(ip)
                break
            except socket.error:
                print("Invalid ip address")
        while True:
            permissions = input("Please enter the permissions you would like to give for this ip. Any combination of r (read) l (list) w (write) and d (delete) are accepted. (r/l/w/d) ").lower()
            modes = "rlwd"
            if set(permissions) <= set(modes):
                break
            else:
                print("You entered a character that wasn't r, l, w, or d, please retry")

        # clean up permission string, make sure no duplicates and sort it in order of rlwd
        clean_permissions = ""
        if "r" in permissions:
            clean_permissions = "r"
        if "l" in permissions:
            clean_permissions = clean_permissions + "l"
        if "w" in permissions:
            clean_permissions = clean_permissions + "w"
        if "d" in permissions:
            clean_permissions = clean_permissions + "d"

        new_endpoint["allowed_ip_addresses"].append({"ip": ip, "permissions": clean_permissions})

        process_ips = prompt_bool("Would you like to specify another IP address? (Y/n) ")

    # query loop for attribute permissions
    process_attributes = prompt_bool("Would you like to specify permissions for LDAP attributes? (Y/n) ")
    while process_attributes:
        # can use same variable for both loops - cheeky!
        attributes = []
        while process_attributes:
            attribute = input("Enter attribute name: ")
            # empty attribute = anon user
            if not attribute:
                confirm_empty = prompt_bool("This will apply permissions to any user, continue? (Y/n) ")
                if confirm_empty:
                    # break out of loop and ask for permissions
                    process_attributes = False
                else:
                    # this gets us back to start of loop
                    continue
            else:
                # if non empty, process as normal
                value = input("Enter attribute value: ")

                attributes.append({"attribute": attribute, "value": value})
                process_attributes = prompt_bool("Would you like to specify another set of attributes? This will require both the previous attributes and the new one to be true (logical AND) (Y/n) ")

        while True:
            permissions = input("Please enter the permissions you would like to give for these attributes. Any combination of r (read) l (list) w (write) and d (delete) are accepted. (r/l/w/d) ").lower()
            modes = "rlwd"
            if set(permissions) <= set(modes):
                break
            else:
                print("You entered a character that wasn't r, l, w, or d, please retry")

        # clean up permission string, make sure no duplicates and sort it in order of rlwd
        clean_permissions = ""
        if "r" in permissions:
            clean_permissions = "r"
        if "l" in permissions:
            clean_permissions = clean_permissions + "l"
        if "w" in permissions:
            clean_permissions = clean_permissions + "w"
        if "d" in permissions:
            clean_permissions = clean_permissions + "d"

        new_endpoint["allowed_attributes"].append({"attribute_requirements": attributes, "permissions": clean_permissions})

        process_attributes = prompt_bool("Would you like to specify another set of attributes? These are independent of other attributes specified (logical OR) (Y/n) ")

    #print(json.dumps(new_endpoint, indent=4))
    # print output
    pretty_print_endpoint(new_endpoint)

    confirmation = prompt_bool("Confirm that you want to insert above endpoint into the JSON file? (Y/n) ")
    if confirmation:
        config_json["endpoints"].append(new_endpoint)
        with open(args.file, "w") as f:
            json.dump(config_json, f, indent=4)

    return 0


def remove_endpoint(args):
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug the config file")
        return 1

    with open(args.file, "r") as f:
        config_json = json.load(f)

    for endpoint in config_json["endpoints"]:
        if endpoint["endpoint_path"] == args.endpoint_path:
            pretty_print_endpoint(endpoint)
            remove_confirm = prompt_bool("Confirm that you want to remove the above endpoint configuration from the file? (Y/n) ")

            if remove_confirm:
                config_json["endpoints"].remove(endpoint)
                with open(args.file, "w") as f:
                    json.dump(config_json, f, indent=4)

            return 0


def server(args):
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug the config file")
        return 1

    with open(args.file, "r") as f:
        config_json = json.load(f)

    if args.server:
        # check if server given can be contacted
        try:
            s = ldap3.Server(args.server)
            conn = ldap3.Connection(s, auto_bind=True)
            conn.unbind()

            config_json["server"] = args.server

            with open(args.file, "w") as f:
                json.dump(config_json, f, indent=4)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            print("Cannot connect to LDAP server - is the address correct?")
    else:
        print(config_json["server"])
    return 0


def convert_authdb_to_ldap_json(args):
    with open(args.authdb_file, "r") as f:
        authdb_json = json.load(f)

    new_config = {
        "server": "",  # leave server blank as it is unneeded
        "endpoints": []
    }

    for vo in authdb_json:
        for bucket in authdb_json[vo]:
            path = "/" + vo + "/" + bucket
            roles = []
            clientnames = []
            remoteaddrs = []
            if "role" in authdb_json[vo][bucket]:
                roles = authdb_json[vo][bucket]["role"]
            if "clientname" in authdb_json[vo][bucket]:
                clientnames = authdb_json[vo][bucket]["clientname"]
            if "remoteaddr" in authdb_json[vo][bucket]:
                remoteaddrs = authdb_json[vo][bucket]["remoteaddr"]

            new_endpoint = {
                "endpoint_path": path,
                "allowed_attributes": [],
                "allowed_ip_addresses": [],
                "propogate_permissions": True  # it propogates down in old format
            }

            for role in roles:
                attribute_requirement = {
                    "attribute_requirements": [
                        {
                            "attribute": "role",
                            "value": role
                        }
                    ],
                    "permissions": roles[role]
                }
                new_endpoint["allowed_attributes"].append(attribute_requirement)

            for clientname in clientnames:
                attribute_requirement = {
                    "attribute_requirements": [
                        {
                            "attribute": "clientname",
                            "value": clientname
                        }
                    ],
                    "permissions": clientnames[clientname]
                }
                new_endpoint["allowed_attributes"].append(attribute_requirement)

            for remoteaddr in remoteaddrs:
                ip = {
                    "ip": remoteaddr,
                    "permissions": remoteaddrs[remoteaddr]
                }
                new_endpoint["allowed_ip_addresses"].append(ip)

            new_config["endpoints"].append(new_endpoint)

    with open(args.output_filename, "w") as f:
        json.dump(new_config, f, indent=4)

    return 0


# top level argument parser
parser = argparse.ArgumentParser()

# is this default okay or mark it as a required option?l
parser.add_argument("-f, --file", type=str, default="./ldap_auth.json", dest="file", help="Location of the JSON configuration file to act on. Defaults to ./ldap_auth.json")
subparsers = parser.add_subparsers(title="subcommands", description="Functions that can be performed on the JSON file")

# parser for verify command
parser_verify = subparsers.add_parser("verify", help="Verify that the JSON file is valid.")
parser_verify.add_argument("--surpress-verify-output", action="store_true", help=argparse.SUPPRESS)  # hidden option to tell us to surpress output
parser_verify.set_defaults(func=verify)

# parser for list command
parser_list = subparsers.add_parser("list", help="List all endpoints in file")
parser_list.set_defaults(func=list_endpoints)

# parser for info command
parser_info = subparsers.add_parser("info", help="Get the configuration information for an endpoint")
parser_info.add_argument("endpoint_path", help="Endpoint path to get info on")
parser_info.add_argument("--json", action="store_true", help="Just print the JSON entry")
parser_info.set_defaults(func=endpoint_info)

# parser for add command
parser_add = subparsers.add_parser("add", help="Add a new endpoint to the authorisation file")
parser_add.add_argument("endpoint_path", help="Endpoint path to add authorisation info for")
parser_add.set_defaults(func=add_endpoint)

# parser for remove command
parser_remove = subparsers.add_parser("remove", help="Remove a new endpoint to the authorisation file")
parser_remove.add_argument("endpoint_path", help="Endpoint path to remove from authorisation file")
parser_remove.set_defaults(func=remove_endpoint)

# parser for server command
parser_server = subparsers.add_parser("server", help="Get the name of the LDAP server or provide a new URI and set a new LDAP server")
parser_server.add_argument("server", nargs="?", help="Supply a server name to set the LDAP server in the configuration")
parser_server.set_defaults(func=server)

# parser for convert command
parser_convert = subparsers.add_parser("convert", help="Convert an old style AuthDB json file into LDAP config json")
parser_convert.add_argument("authdb_file", help="Path to AuthDB file to convert to LDAP config")
parser_convert.add_argument("output_filename", help="Path to where you want to store the converted output file")
parser_convert.set_defaults(func=convert_authdb_to_ldap_json)

args = parser.parse_args()
args.func(args)
