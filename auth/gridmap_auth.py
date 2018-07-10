#!/usr/bin/python
# -*- coding: utf-8 -*-

# Authorization plugin that uses an authDB and grid-mapfile
# usage:
# gridmap_auth.py <clientname> <remoteaddr> <fqan1> .. <fqanN>
#
# Return value means:
# 0 --> access is GRANTED
# nonzero --> access is DENIED
#

import sys
import json


# A class that implements a grid-mapfile loaded from a text file during the initialization of the module.
class _Authlist(object):
    GridMapFile = "/etc/grid-security/grid-mapfile"
    d = {}

    def __init__(self):
        print "Loading Gridmap file from " + self.GridMapFile
        with open(self.GridMapFile) as f:
            for line in f:
                #  Gridmap file looks like "/O=dutchgrid/O=users/O=nikhef/CN=Dominik Duda" atlasuser
                #  Split on '" ' in the middle and then strip of the leading " and trailing \n
                DN = (line.rsplit('" ')[0]).strip('"')
                Role = (line.split('" ')[-1]).strip('\n')
                self.d[DN] = Role
#               print(self.d)

    def authenticateUser(self, DN):
        return DN in self.d

    def getRole(self, DN):
        return self.d[DN]


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
        with open("/etc/grid-security/authdb.json", "r") as f:
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


# Initialize a global instance of the authlist and authjson class, to be used inside the isallowed() function
myauthlist = _Authlist()
myauthjson = _AuthJSON()


def isallowed(clientname="unknown", remoteaddr="nowhere", resource="none", mode="0", fqans=None, keys=None):
#    print "clientname", clientname
#    print "remote address", remoteaddr
#    print "fqans", fqans
#    print "keys", keys
#    print "mode", mode
#    print "resource", resource

    result = myauthjson.auth_info_for_path(resource)
    if result is None:
        # failed to match anything
        print("nada")
        return 1

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

    for item in auth_info["allowed_attributes"]:
        # assume True (meaning empty list matches)
        # if we get an attribute that doesn't match then we fail this set of attributes
        match = True
        for attribute in item["attribute_requirements"]:
            print(attribute)
            # if there is a clientname requirement and it doesn't match then reject
            if attribute["attribute"] == "clientname" and attribute["value"] != clientname:
                match = False
                break

            # if there is a role requirement and if not in gridmap or it doesn't match then reject
            if attribute["attribute"] == "role" and (not myauthlist.authenticateUser(clientname) or attribute["value"] != myauthlist.getRole(clientname)):
                match = False
                break

        if match and mode in item["permissions"]:
            # if we match on all attributes for this spec and the mode matches the permissions then let them in!
            return 0

    # if we haven't matched yet then don't let them in >:(
    return 1


# ------------------------------
if __name__ == "__main__":
    r = isallowed(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:])
    print r
    sys.exit(r)
