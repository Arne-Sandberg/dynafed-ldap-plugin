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

        # Now need to check that it's valid config on top of being valid JSON
        if "server" not in config_json:
            print("Server not specified")
            return 1

        if "prefix" not in config_json:
            print("Federation prefix not specified")
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
                print("Endpoints should be a list of objects, endpoint list index " +
                      str(index) + " is not an object")
                return 1

            if "endpoint_path" not in endpoint:
                print("No endpoint path specified for endpoint list index " +
                      str(index))
                return 1

            if not isinstance(endpoint["endpoint_path"], basestring):
                print(str(endpoint["endpoint_path"]) + " is not a string, " +
                      "endpoint_path should be a string for endpoint list index " +
                      str(index))
                return 1

            # TODO: bother regexing the endpoint path?

            if "allowed_ip_addresses" not in endpoint:
                print("No allowed ip addresses specified for endpoint list index " +
                      str(index))
                return 1

            if not isinstance(endpoint["allowed_ip_addresses"], list):
                print(str(endpoint["allowed_ip_addresses"]) + " is not a list, " +
                      "allowed_ip_addresses should be a list for endpoint list index " +
                      str(index))
                return 1

            for ip_index, allowed_ip_address in enumerate(endpoint["allowed_ip_addresses"]):
                if not isinstance(allowed_ip_address, dict):
                    print("allowed_ip_addresses should be a list of objects, " +
                          "allowed_ip_addresses list index " + str(ip_index) +
                          " endpoint list index " + str(index) +
                          " has an allowed_ip_addresses list item that is not an object")
                    return 1

                if "ip" not in allowed_ip_address:
                    print("No ip specified in allowed_ip_addresses list index " +
                          str(ip_index) + " endpoint list index " + str(index))
                    return 1

                if "permissions" not in allowed_ip_address:
                    print("No permissions specified in allowed_ip_addresses list index " +
                          str(ip_index) + " endpoint list index " + str(index))
                    return 1

                if not isinstance(allowed_ip_address["ip"], basestring):
                    print("allowed_ip_address ip should be a string, in allowed_ip_addresses list index " +
                          str(ip_index) + " endpoint list index " + str(index))
                    return 1

                # use sets to check that only r, l, w and d values are allowed, it does allow for empty permissions
                if not set(allowed_ip_address["permissions"]) <= set([u"r", u"w", u"l", u"d"]):
                    print("allowed_ip_address permissions should be a string " +
                          "containing any of the modes r (read) l (list) w " +
                          "(write) d (delete), in allowed_ip_address list index " +
                          str(ip_index) + " endpoint list index " + str(index))
                    return 1

            if "propogate_permissions" in endpoint and not isinstance(endpoint["propogate_permissions"], bool):
                print(str(endpoint["propogate_permissions"]) + " is not a bool, " +
                      "propogate_permissions should be a bool for endpoint list index " + str(index))
                return 1

            if "allowed_attributes" not in endpoint:
                print("No allowed attributes specified for endpoint list index " + str(index))
                return 1

            if not isinstance(endpoint["allowed_attributes"], list):
                print(str(endpoint["allowed_attributes"]) + " is not a list, " +
                      "allowed_attributes should be a list for endpoint list index " + str(index))
                return 1

            for attr_index, allowed_attributes in enumerate(endpoint["allowed_attributes"]):
                if not isinstance(allowed_attributes, dict):
                    print("allowed_attributes should be a list of objects, " +
                          "attribute_requirements list index " + str(attr_index) +
                          " endpoint list index " + str(index) +
                          " has an allowed_attributes list item that is not an object")
                    return 1

                if "attribute_requirements" not in allowed_attributes:
                    print("No attribute_requirements specified in attribute_requirements list index " +
                          str(attr_index) + " endpoint list index " + str(index))
                    return 1

                if "permissions" not in allowed_attributes:
                    print("No permissions specified in attribute_requirements list index " +
                          str(attr_index) + " endpoint list index " + str(index))
                    return 1

                if not isinstance(allowed_attributes["attribute_requirements"], dict):
                    print("attribute_requirements should be a dict, in attribute_requirements list index " +
                          str(attr_index) + " endpoint list index " + str(index))
                    return 1

                if check_valid_attribute_condition(allowed_attributes["attribute_requirements"], attr_index, index) == 1:
                    return 1

                # use sets to check that only r, l, w and d values are allowed, it does allow for empty permissions
                if not set(allowed_attributes["permissions"]) <= set([u"r", u"w", u"l", u"d"]):
                    print("attribute_requirements permissions should be a string " +
                          "containing any of the modes r (read) l (list) w (write) " +
                          "d (delete), in attribute_requirements list index " +
                          str(attr_index) + " endpoint list index " + str(index))
                    return 1

        print("Config file is valid")
        # restore stdout
        sys.stdout = sys.__stdout__
        return 0

    except ValueError:
        print("Invalid JSON")


def check_valid_attribute_condition(attribute_condition, attr_index, endpoint_index):
    if not isinstance(attribute_condition, dict):
        print("Atrribute conditions should be dicts, in attribute_requirements list index " +
              str(attr_index) + " endpoint list index " + str(endpoint_index))
        return 1

    # empty is valid - means no attributes are required to match
    if len(attribute_condition) == 0:
        return 0

    if (("attribute" in attribute_condition and "value" not in attribute_condition) or
       ("value" in attribute_condition and "attribute" not in attribute_condition)):
        print("Atrribute specifications should specify both an attribute name and a value" +
              ", in attribute_requirements list index " + str(attr_index) +
              " endpoint list index " + str(endpoint_index))
        return 1

    if "attribute" in attribute_condition and not isinstance(attribute_condition["attribute"], basestring):
        print("attribute should be a string, attribute_requirements list index " +
              str(attr_index) + " endpoint list index " + str(endpoint_index))
        return 1

    if (("attribute" not in attribute_condition and
         "or" not in attribute_condition and
         "and" not in attribute_condition)):
        print("Atrribute conditions should either be an attribute-value pair, " +
              "or an 'or' condition list or an 'and' condition list" +
              ", in attribute_requirements list index " + str(attr_index) +
              " endpoint list index " + str(endpoint_index))
        return 1

    operator = "or" if "or" in attribute_condition else ""
    operator = "and" if "and" in attribute_condition else operator

    if (operator in attribute_condition and not isinstance(attribute_condition[operator], list)):
        print("OR or AND atrribute conditions should contain a list (of attribute conditions)" +
              ", item in attribute_requirements list index " + str(attr_index) +
              " endpoint list index " + str(endpoint_index) + " is not a list")
        return 1

    if (operator in attribute_condition):
        for sub_attribute_condition in attribute_condition[operator]:
            check_valid_attribute_condition(sub_attribute_condition, attr_index, endpoint_index)

    return 0


def list_endpoints(args):
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return 1

    with open(args.file, "r") as f:
        config_json = json.load(f)

    for endpoint in config_json["endpoints"]:
        print(endpoint["endpoint_path"])

    return 0


def endpoint_info(args):
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return 1

    with open(args.file, "r") as f:
        config_json = json.load(f)

    for endpoint in config_json["endpoints"]:
        if endpoint["endpoint_path"] == args.endpoint_path:
            print(json.dumps(endpoint, indent=4))
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


def prompt_permissions(message):
    while True:
        permissions = input(message).lower()
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

    return clean_permissions


def create_attribute_condition():
    while True:
        user_selection = input("\nWould you like to create an OR condition, AND condition or specify an attribute-value pair? \n"
                               "1) OR\n"
                               "2) AND\n"
                               "3) Attribute-value pair\n")
        if (user_selection != "1" or user_selection != "2" or
                user_selection != "3"):
            break
        else:
            print("Please enter a number 1-3")

    # OR condition
    if user_selection == "1":
        operation = "or"
        condition = {
            "or": []
        }

    # AND condition
    if user_selection == "2":
        operation = "and"
        condition = {
            "and": []
        }

    # Attribute-value pair
    if user_selection == "3":
        condition = {
            "attribute": "",
            "value": ""
        }
        # if the user is specifying an attribute
        # we can't ask for more conditions, so return
        return condition

    # OR and AND conditions need to ask for sub conditions
    if user_selection == "1" or "user_selection" == 2:
        print("Please add an attribute condition to this " + operation + "condition")

        add_condition = True
        while add_condition:
            # recurse and prompt if they want to add another condition at this level
            attribute_condition = create_attribute_condition()
            condition[operation].append(attribute_condition)
            add_condition = prompt_bool("Would you like to add another attribute condition to this " +
                                        operation + "condition? (Y/n)")

    return condition


def add_endpoint(args):
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return 1

    with open(args.file, "r") as f:
        config_json = json.load(f)

    # need to create an endpoint entry by querying the user
    new_endpoint = {
        "endpoint_path": args.endpoint_path,
        "allowed_attributes": [],
        "allowed_ip_addresses": [],
        "propogate_permissions": True
    }

    print("Creating config for endpoint " + args.endpoint_path + "\n")

    propogate_permissions = prompt_bool("Should the permissions specified for this "
                                        "path be applied to any of it's children/"
                                        "subfolders not specified in this file? (Y/n) ")
    new_endpoint["propogate_permissions"] = propogate_permissions

    # query loop for ip address permissions
    process_ips = prompt_bool("Would you like to specify permissions "
                              "for specific IP addresses? (Y/n) ")
    while process_ips:
        while True:
            ip = input("Enter ip address: ")
            # TODO ipv6?
            try:
                socket.inet_aton(ip)
                break
            except socket.error:
                print("Invalid ip address")

        permissions = prompt_permissions("Please enter the permissions you would "
                                         "like to give for this ip. Any combination "
                                         "of r (read) l (list) w (write) and d "
                                         "(delete) are accepted. (r/l/w/d) ")
        new_endpoint["allowed_ip_addresses"].append({"ip": ip, "permissions": permissions})
        process_ips = prompt_bool("Would you like to specify another IP address? (Y/n) ")

    # query loop for attribute permissions
    process_attributes = prompt_bool("Would you like to specify permissions "
                                     "for LDAP attributes? (Y/n) ")

    while process_attributes:
        attribute_condition = create_attribute_condition()
        permissions = prompt_permissions("Please enter the permissions you would "
                                         "like to give for these attributes. Any "
                                         "combination of r (read) l (list) w (write) "
                                         "and d (delete) are accepted. (r/l/w/d) ")

        new_endpoint["allowed_attributes"].append({"attribute_requirements": attribute_condition,
                                                   "permissions": permissions})

    process_attributes = prompt_bool("Would you like to specify another "
                                     "attribute condition with different "
                                     "permissions for this endpoint? (Y/n)")

    print(json.dumps(new_endpoint, indent=4))

    confirmation = prompt_bool("Confirm that you want to insert above "
                               "endpoint into the JSON file? (Y/n) ")
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
        print("Config file not valid, please use the verify function to debug")
        return 1

    with open(args.file, "r") as f:
        config_json = json.load(f)

    for endpoint in config_json["endpoints"]:
        if endpoint["endpoint_path"] == args.endpoint_path:
            print(json.dumps(endpoint, indent=4))
            remove_confirm = prompt_bool("Confirm that you want to remove the above "
                                         "endpoint configuration from the file? (Y/n) ")

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
        print("Config file not valid, please use the verify function to debug")
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


def prefix(args):
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return 1

    with open(args.file, "r") as f:
        config_json = json.load(f)

    if args.prefix:
        # check if server given can be contacted
        with open(args.file, "w") as f:
            json.dump(config_json, f, indent=4)
    else:
        print(config_json["prefix"])
    return 0


def convert_authdb_to_ldap_json(args):
    with open(args.authdb_file, "r") as f:
        authdb_json = json.load(f)

    new_config = {
        "server": "",  # leave server blank as it is unneeded
        "endpoints": [],
        "prefix": args.base_prefix
    }

    # add some default endpoints like / and bucket_prefix to the file

    base_endpoint = {
        "endpoint_path": "/",
        "allowed_attributes": [
            {
                "attribute_requirements": {},
                "permissions": "rl"
            }
        ],
        "allowed_ip_addresses": [],
        "propogate_permissions": False
    }
    new_config["endpoints"].append(base_endpoint)

    if "bucket_prefix" in args:
        if args.bucket_prefix[0] == "/":
            prefix = args.bucket_prefix
        else:
            prefix = "/" + args.bucket_prefix
        bucket_prefix_endpoint = {
            "endpoint_path": prefix,
            "allowed_attributes": [
                {
                    "attribute_requirements": {},
                    "permissions": "rl"
                }
            ],
            "allowed_ip_addresses": [],
            "propogate_permissions": False
        }
        new_config["endpoints"].append(bucket_prefix_endpoint)

    for vo in authdb_json:
        vo_path = "/" + vo
        if "bucket_prefix" in args:
            if args.bucket_prefix[0] == "/":
                vo_path = args.bucket_prefix + vo_path
            else:
                vo_path = "/" + args.bucket_prefix + vo_path
        vo_endpoint = {
            "endpoint_path": vo_path,
            "allowed_attributes": [
                {
                    "attribute_requirements": {},
                    "permissions": "rl"
                }
            ],
            "allowed_ip_addresses": [],
            "propogate_permissions": False
        }
        new_config["endpoints"].append(vo_endpoint)

        for bucket in authdb_json[vo]:
            path = vo + "/" + bucket
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

            # old format was basically a list of single requirements mapped to
            # permission strings. We can combine everything by iterating through
            # everything and placing them in a list corresponding to the permissions,
            # then construct or conditions per different permission string
            permissions = {}

            for role in roles:
                permission_string = roles[role]
                attribute = {
                    "attribute": "role",
                    "value": role
                }
                if permission_string in permissions:
                    permissions[permission_string].append(attribute)
                else:
                    permissions[permission_string] = [attribute]

            for clientname in clientnames:
                permission_string = clientnames[clientname]
                attribute = {
                    "attribute": "clientname",
                    "value": clientname
                }
                if permission_string in permissions:
                    permissions[permission_string].append(attribute)
                else:
                    permissions[permission_string] = [attribute]

            for permission in permissions:
                or_condition = {
                    "attribute_requirements": {
                        "or": []
                    },
                    "permissions": permission
                }
                for attribute in permissions[permission]:
                    or_condition["attribute_requirements"]["or"].append(attribute)

                new_endpoint["allowed_attributes"].append(or_condition)

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


def add_users(args):
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return 1

    with open(args.file, "r") as f:
        config_json = json.load(f)

    create_endpoint = False
    endpoint = {}
    for endpoint_i in config_json["endpoints"]:
        if args.endpoint_path == endpoint_i["endpoint_path"]:
            endpoint = endpoint_i
    if not endpoint:
        create_endpoint = prompt_bool("Endpoint supplied does not exist in the config, would you like to create one? (Y/n)")

        if not create_endpoint:
            print("Exited without modifying config file")
            return 0

    if create_endpoint:
        endpoint = {
            "endpoint_path": args.endpoint_path,
            "allowed_attributes": [],
            "allowed_ip_addresses": [],
            "propogate_permissions": True
        }

        print("Creating config for endpoint " + args.endpoint_path + "\n")

        propogate_permissions = prompt_bool("Should the permissions specified for this "
                                            "path be applied to any of it's children/"
                                            "subfolders not specified in this file? (Y/n) ")
        endpoint["propogate_permissions"] = propogate_permissions
        config_json["endpoints"].append(endpoint)

    # check if there are existing rl and rlwd permission sections
    rl_attribute_condition = {}
    rlwd_attribute_condition = {}
    for allowed_attributes in endpoint["allowed_attributes"]:
        # it doesn't matter too much if the user has decided to create
        # different allowed_attributes with the same permission string
        # we just add to the first one we find

        # sort before checking to ensure we get all valid combinations
        if "".join(sorted(allowed_attributes["permissions"])) == "lr":
            rl_attribute_condition = allowed_attributes

        if "".join(sorted(allowed_attributes["permissions"])) == "dlrw":
            rlwd_attribute_condition = allowed_attributes

    # do read users first
    if "read_users" in args and args.read_users:
        # do we add to an existing allowed_attributes entry?
        if rl_attribute_condition:
            endpoint["allowed_attributes"].remove(rl_attribute_condition)

            # need to deal with whatever is already in the attribute condition
            # and create an or as the top layer with which we can add
            # our new users to
            if "attribute" in rl_attribute_condition["attribute_requirements"]:
                existing_attribute_name = rl_attribute_condition["attribute_requirements"]["attribute"]
                existing_attribute_value = rl_attribute_condition["attribute_requirements"]["value"]

                rl_attribute_condition = {
                    "attribute_requirements": {
                        "or": []
                    },
                    "permissions": "rl"
                }
                attribute = {
                    "attribute": existing_attribute_name,
                    "value": existing_attribute_value
                }
                rl_attribute_condition["attribute_requirements"]["or"].append(attribute)

            if "and" in rl_attribute_condition["attribute_requirements"]:
                and_condition = rl_attribute_condition["attribute_requirements"]["and"]

                rl_attribute_condition = {
                    "attribute_requirements": {
                        "or": []
                    },
                    "permissions": "rl"
                }
                rl_attribute_condition["attribute_requirements"]["or"].append(and_condition)

            # don't need to do anything for existing or condition, just add additional
            # users to it like normal below

        else:
            rl_attribute_condition = {
                "attribute_requirements": {
                    "or": []
                },
                "permissions": "rl"
            }

        for user in args.read_users:
            attribute = {
                "attribute": args.username_attr,
                "value": user
            }
            rl_attribute_condition["attribute_requirements"]["or"].append(attribute)

        endpoint["allowed_attributes"].append(rl_attribute_condition)

    # now do write users
    if "write_users" in args and args.write_users:
        # do we add to an existing allowed_attributes entry?
        if rlwd_attribute_condition:
            endpoint["allowed_attributes"].remove(rlwd_attribute_condition)

            # need to deal with whatever is already in the attribute condition
            # and create an or as the top layer with which we can add
            # our new users to
            if "attribute" in rlwd_attribute_condition["attribute_requirements"]:
                existing_attribute_name = rlwd_attribute_condition["attribute_requirements"]["attribute"]
                existing_attribute_value = rlwd_attribute_condition["attribute_requirements"]["value"]

                rlwd_attribute_condition = {
                    "attribute_requirements": {
                        "or": []
                    },
                    "permissions": "rlwd"
                }
                attribute = {
                    "attribute": existing_attribute_name,
                    "value": existing_attribute_value
                }
                rlwd_attribute_condition["attribute_requirements"]["or"].append(attribute)

            if "and" in rlwd_attribute_condition["attribute_requirements"]:
                and_condition = rlwd_attribute_condition["attribute_requirements"]["and"]

                rlwd_attribute_condition = {
                    "attribute_requirements": {
                        "or": []
                    },
                    "permissions": "rlwd"
                }
                rlwd_attribute_condition["attribute_requirements"]["or"].append(and_condition)

            # don't need to do anything for existing or condition, just add additional
            # users to it like normal below

        else:
            rlwd_attribute_condition = {
                "attribute_requirements": {
                    "or": []
                },
                "permissions": "rlwd"
            }

        for user in args.read_users:
            attribute = {
                "attribute": args.username_attr,
                "value": user
            }
            rlwd_attribute_condition["attribute_requirements"]["or"].append(attribute)

        endpoint["allowed_attributes"].append(rlwd_attribute_condition)

    with open(args.file, "w") as f:
        json.dump(config_json, f, indent=4)

    return 0

# top level argument parser
parser = argparse.ArgumentParser()

# is this default okay or mark it as a required option?
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
parser_info.set_defaults(func=endpoint_info)

# parser for add command
parser_add = subparsers.add_parser("add", help="Add a new endpoint to the authorisation file")
parser_add.add_argument("endpoint_path", help="Endpoint path to add authorisation info for")
parser_add.set_defaults(func=add_endpoint)

# parser for addusers command
parser_addusers = subparsers.add_parser("addusers", help="Add a new users to an endpoint in the authorisation file")
parser_addusers.add_argument("endpoint_path", help="Endpoint path to add users to the authorisation info")
parser_addusers.add_argument("-r, --read-users", dest="read_users", nargs="+", help="Supply usernames for users who should have read and list permissions")
parser_addusers.add_argument("-w, --write-users", dest="write_users", nargs="+", help="Supply usernames for users who should have read, list, write and delete permissions")
parser_addusers.add_argument("-u, --username-attr", type=str, dest="username_attr", required=True, help="The name of the attribute in which the username is stored.")
parser_addusers.set_defaults(func=add_users)

# parser for remove command
parser_remove = subparsers.add_parser("remove", help="Remove a new endpoint to the authorisation file")
parser_remove.add_argument("endpoint_path", help="Endpoint path to remove from authorisation file")
parser_remove.set_defaults(func=remove_endpoint)

# parser for server command
parser_server = subparsers.add_parser("server", help="Get the name of the LDAP server or provide a new URI and set a new LDAP server")
parser_server.add_argument("server", nargs="?", help="Supply a server name to set the LDAP server in the configuration")
parser_server.set_defaults(func=server)

# parser for prefix command
parser_server = subparsers.add_parser("prefix", help="Get the federation prefix for DynaFed or provide a new prefix. This will be prepended to all endpoints")
parser_server.add_argument("prefix", nargs="?", help="Supply a prefix to set the federation prefix in the configuration")
parser_server.set_defaults(func=server)

# parser for convert command
parser_convert = subparsers.add_parser("convert", help="Convert an old style AuthDB json file into LDAP config json")
parser_convert.add_argument("authdb_file", help="Path to AuthDB file to convert to LDAP config")
parser_convert.add_argument("output_filename", help="Path to where you want to store the converted output file")
parser_convert.add_argument("--base-prefix", dest="base_prefix", required=True, help="Base federation prefix to be added to config")
parser_convert.add_argument("--bucket-prefix", dest="bucket_prefix", help="Path prefix to be prepended to all paths (e.g. authentication prefix 'cert'")
parser_convert.set_defaults(func=convert_authdb_to_ldap_json)

if __name__ == "__main__":
    args = parser.parse_args()
    args.func(args)
