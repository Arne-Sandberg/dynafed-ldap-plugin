#!/usr/bin/env python
from __future__ import print_function, unicode_literals
import Tkinter as tk
import ttk
import json
import argparse
import tabulate


def pretty_print_endpoint(endpoint):
    output_str = ""
    output_str += ("Endpoint path: " + endpoint["endpoint_path"] + "\n")
    if "propogate_permissions" in endpoint:
        output_str += ("Propogate permissions: " + str(endpoint["propogate_permissions"]))
    else:
        output_str += ("Propogate permissions: True")

    output_str += ("\nAllowed ips")
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

    output_str += (tabulate(ip_table, headers=["read", "list", "write", "delete"]))
    output_str += ("\nAllowed Attributes")
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

    output_str += (tabulate(attribute_table, headers=["read", "list", "write", "delete"]))
    return output_str


class Application(tk.Frame):
    # different interfaces needed for different types of node, keep track of IDs here

    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        self.master.title("Edit JSON config")
        self.pack()
        self.createWidgets()

        self.endpoint_ids = []
        self.propogate_permissions_ids = []
        self.permissions_ids = []
        self.ip_ids = []
        self.allowed_attribute_set_ids = []
        self.attribute_ids = []
        self.value_ids = []

    def createWidgets(self):
        with open(args.file, "r") as f:
            config_json = json.load(f)

        self.jsonviewer = ttk.Treeview(selectmode="browse")

        for endpoint in config_json["endpoints"]:
            endpoint_id = self.jsonviewer.insert("", "end", text=endpoint["endpoint_path"])
            self.endpoint_ids.append(endpoint_id)

            propogate_permissions_id = self.jsonviewer.insert(endpoint_id, "end", text="propogate_permissions")
            propogate_permissions_value_id = self.jsonviewer.insert(propogate_permissions_id, "end", text=str(endpoint["propogate_permissions"]))
            self.propogate_permissions_ids.append(propogate_permissions_value_id)

            allowed_ip_addresses_id = self.jsonviewer.insert(endpoint_id, "end", text="allowed_ip_addresses")

            allowed_attributes_id = self.jsonviewer.insert(endpoint_id, "end", text="allowed_attributes")

            for ip in endpoint["allowed_ip_addresses"]:
                ip_id = self.jsonviewer.insert(allowed_ip_addresses_id, "end", text=ip["ip"])
                permissions_id = self.jsonviewer.insert(ip_id, "end", text=ip["permissions"])
                self.ip_ids.append(ip_id)
                self.permissions_ids.append(permissions_id)

            for index, attribute_set in enumerate(endpoint["allowed_attributes"]):
                allowed_attribute_set_id = self.jsonviewer.insert(allowed_attributes_id, "end", text="Allowed attribute set " + str(index + 1))
                self.allowed_attribute_set_ids.append(allowed_attribute_set_id)

                attribute_requirements_id = self.jsonviewer.insert(allowed_attribute_set_id, "end", text="attribute_requirements")
                for attribute in attribute_set["attribute_requirements"]:
                    attribute_id = self.jsonviewer.insert(attribute_requirements_id, "end", text=attribute["attribute"])
                    value_id = self.jsonviewer.insert(attribute_id, "end", text=attribute["value"])

                    self.attribute_ids.append(attribute_id)
                    self.value_ids.append(value_id)

                permissions_label_id = self.jsonviewer.insert(allowed_attribute_set_id, "end", text="permissions")
                permissions_id = self.jsonviewer.insert(permissions_label_id, "end", text=attribute_set["permissions"])
                self.permissions_ids.append(permissions_id)


        self.jsonviewer.pack(side=tk.LEFT, expand=True)
        self.jsonviewer.bind("<ButtonRelease-1>", self.selectionChange)
        self.jsonviewer.bind("<KeyRelease>", self.selectionChange)

        self.quitButton = tk.Button(self, text='Quit', command=self.quit)
        self.quitButton.pack(side=tk.RIGHT)

    def selectionChange(self, event):
        item = self.jsonviewer.focus()
        print("you clicked on", self.jsonviewer.item(item,"text"))

        # decide which editing gui to display

        if item in self.endpoint_ids:
            pass

        if item in self.propogate_permissions_ids:
            pass

        if item in self.permissions_ids:
            pass

        if item in self.ip_ids:
            pass

        if item in self.allowed_attribute_set_ids:
            pass

        if item in self.attribute_ids:
            pass

        if item in self.value_ids:
            pass



# top level argument parser
parser = argparse.ArgumentParser()

# is this default okay or mark it as a required option?l
parser.add_argument("-f, --file", type=str, default="./ldap_auth.json", dest="file", help="Location of the JSON configuration file to act on. Defaults to ./ldap_auth.json")

if __name__ == "__main__":
    args = parser.parse_args()
    app = Application()
    app.mainloop()