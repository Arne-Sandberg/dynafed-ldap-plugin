#!/usr/bin/python
# -*- coding: utf-8 -*-

# A DynaFed plugin that uses Shibboleth attributes from environment variables
# passed py the keys variable to compare to a JSON file to determine whether
# a user with certain attributes can access a resource
# usage:
# shib_auth.py <clientname> <remoteaddr> <fqan1> .. <fqanN>
#
# Return value means:
# 0 --> access is GRANTED
# nonzero --> access is DENIED
#

import sys
import json
import time

# A class that one day may implement an authorization list loaded
# from a file during the initialization of the module.
# If this list is written only during initialization, and used as a read-only thing
# no synchronization primitives (e.g. semaphores) are needed, and the performance will be maximized


# use this to strip trailing slashes so that we don't trip up any equalities due to them
def strip_end(string, suffix):
    if string.endswith(suffix):
        return string[:-len(suffix)]
    else:
        return string


class _AuthJSON(object):
    auth_dict = {}
    path_list = []

    def __init__(self):
        with open("/etc/ugr/conf.d/shib_auth.json", "r") as f:
            self.auth_dict = json.load(f)
            prefix = self.auth_dict["prefix"]
            # prepopulate path list so we don't repeatedly parse it
            for endpoint in self.auth_dict["endpoints"]:
                self.path_list.append(strip_end(strip_end(prefix, "/") + endpoint["endpoint_path"], "/"))

    # we want to apply the auth that matches the path most closely,
    # so we have to search the dict for path prefixes that match
    # the path we supply
    # aka we propogate permissions down unless the user has specified
    # different permissions for a child directory
    def auth_info_for_path(self, path):
        stripped_path = strip_end(path, "/")
        split_path = stripped_path.split("/")
        prefix = self.auth_dict["prefix"]
        i = 0
        while i < len(split_path):
            p = ""
            if i == 0:
                p = stripped_path
            else:
                # the higher i is the closer we're getting to the base of the path
                # so take off successive elements from end of split path list
                p = "/".join(split_path[:-i])

            if p in self.path_list:
                for endpoint in self.auth_dict["endpoints"]:
                    if strip_end(strip_end(prefix, "/") + endpoint["endpoint_path"], "/") == p:
                        return {"path": p, "auth_info": endpoint}
            i += 1


# Initialize a global instance of the authlist class, to be used inside the isallowed() function
myauthjson = _AuthJSON()


# return true or false based on condition
def process_condition(condition, keys):
    # empty list = don't check any attributes, so auto match
    if len(condition) == 0:
        return True
    if "attribute" in condition:
        # only one attribute to check
        # we prepended env.SHIB_ to all attributes in shib config so lcgdm-dav could parse them out
        # so we need to add env.SHIB_ to attributes from JSON file to match them
        if "env.SHIB_" + condition["attribute"] not in keys or keys["env.SHIB_" + condition["attribute"]] != condition["value"]:
            return False
        else:
            return True
    if "or" in condition:
        # need to match one of anything in the list, so moment we match something
        # return true, if we finish without matching nothing matched so return
        # false
        match_or = condition["or"]
        for or_condition in match_or:
            match = process_condition(or_condition, keys)
            if match:
                return True
        return False
    if "and" in condition:
        # need to match everything in the list, so moment we don't match return
        # false, if we escape without returning false then everything must
        # have been true so return true
        match_and = condition["and"]
        for and_condition in match_and:
            match = process_condition(and_condition, keys)
            if not match:
                return False
        return True
    # TODO: extend to other operators if we need them?


# The main function that has to be invoked from ugr to determine if a request
# has to be performed or not
def isallowed(clientname="unknown", remoteaddr="nowhere", resource="none", mode="0", fqans=None, keys=None):
    start_time = time.time()
    print clientname
    print resource
    print keys
    # keys is a tuple of tuples, change to a dict for easier processing
    keys = dict(keys)

    result = myauthjson.auth_info_for_path(resource)
    auth_info = result["auth_info"]
    matched_path = result["path"]
    if strip_end(matched_path, "/") != strip_end(resource, "/") and "propogate_permissions" in auth_info and not auth_info["propogate_permissions"]:
        # if matched_path != resource then it is a parent directory. if the
        # parent directory does not want to propogate permissions then deny
        # access
        # mainly need this to allow top-level access to the federation
        # without defaulting so that the entire federation is readable
        # might be useful elsewhere too
        return 1

    for ip in auth_info["allowed_ip_addresses"]:
        if ip["ip"] == remoteaddr and mode in ip["permissions"]:
            return 0

    # if shib auth was successful we should always have something here, but just in case...
    if not keys:
        return 1

    for item in auth_info["allowed_attributes"]:
        # use process_condition to check whether we match or not
        condition = item["attribute_requirements"]
        match = process_condition(condition, keys)

        if match and mode in item["permissions"]:
            # for testing, so we can see how long the plugin takes
            print "shib match: " + str(time.time() - start_time)

            # if we match on all attributes for this spec and the mode matches the permissions then let them in!
            return 0

    # if we haven't matched on IP or via Shib attributes then don't let them in >:(
    return 1


# ------------------------------
if __name__ == "__main__":
    r = isallowed(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:])
    sys.exit(r)
