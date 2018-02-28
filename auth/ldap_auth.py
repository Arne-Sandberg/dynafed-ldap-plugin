#!/usr/bin/python
# -*- coding: utf-8 -*-

# A DynaFed that contacts an LDAP server and uses a JSON file
# to determine whether a user with certain attributes can
# access a resource
# usage:
# ldap_auth.py <clientname> <remoteaddr> <fqan1> .. <fqanN>
#
# Return value means:
# 0 --> access is GRANTED
# nonzero --> access is DENIED
#

import sys
import json
import ldap3
import time
from cachetools import TTLCache

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
        with open("/etc/ugr/conf.d/ldap_auth.json", "r") as f:
            self.auth_dict = json.load(f)
            # prepopulate path list so we don't repeatedly parse it
            for endpoint in self.auth_dict["endpoints"]:
                self.path_list.append(endpoint["endpoint_path"])

    # we want to apply the auth that matches the path most closely,
    # so we have to search the dict for path prefixes that match
    # the path we supply
    # aka we propogate permissions down unless the user has specified
    # different permissions for a child directory
    def auth_info_for_path(self, path):
        stripped_path = strip_end(path, "/")
        split_path = stripped_path.split("/")
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
                    if endpoint["endpoint_path"] == p:
                        return {"path": p, "auth_info": endpoint}
            i += 1


# Initialize a global instance of the authlist class, to be used inside the isallowed() function
myauthjson = _AuthJSON()

# initialise server outside of isallowed so to reduce set-up/tear-down costs
s = ldap3.Server(myauthjson.auth_dict["server"])
c = ldap3.Connection(s, client_strategy=ldap3.RESTARTABLE)
c.open()
c.start_tls()

# ldap details remain in cache for 30 mins
cache = TTLCache(maxsize=256, ttl=1800)


# The main function that has to be invoked from ugr to determine if a request
# has to be performed or not
def isallowed(clientname="unknown", remoteaddr="nowhere", resource="none", mode="0", fqans=None, keys=None):
    start_time = time.time()
    print clientname
    print resource

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

    if clientname in cache:
        # in cache, don't need to do LDAP search
        entries = cache[clientname]
    else:
        c.search("dc=fed,dc=cclrc,dc=ac,dc=uk", "(cn=" + clientname + ")", attributes=ldap3.ALL_ATTRIBUTES)
        entries = c.entries
        cache.update([(clientname, entries)])

    print entries

    if len(entries) == 1:
        # this should always happen (since we're searching on username) but just to be sure
        user_info = entries[0]
        for item in auth_info["allowed_attributes"]:
            # assume True (meaning empty list matches)
            # if we get an attribute that doesn't match then we fail this set of attributes
            match = True
            for attribute in item["attribute_requirements"]:
                if user_info[attribute["attribute"]] != attribute["value"]:
                    match = False

            if match and mode in item["permissions"]:
                print "match!"
                # for testing, so we can see how long doing LDAP search + match takes
                print time.time() - start_time
                # if we match on all attributes for this spec and the mode matches the permissions then let them in!
                return 0

    # if we haven't matched on IP or via LDAP attributes then don't let them in >:(
    return 1


# ------------------------------
if __name__ == "__main__":
    r = isallowed(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:])
    sys.exit(r)
