#!/usr/bin/env python
from __future__ import print_function, unicode_literals
import Tkinter as tk
import ttk
import json
import argparse


class Application(tk.PanedWindow):
    # different interfaces needed for different types of node, keep track of IDs here

    def __init__(self, master=None):
        tk.PanedWindow.__init__(self, master)
        self.master.title("Edit JSON config")

        with open(args.file, "r") as f:
            self.config_json = json.load(f)

        self.pack(fill=tk.BOTH, expand=1)
        self.createWidgets()

    def createWidgets(self):
        self.jsonviewer = ttk.Treeview(selectmode="browse")

        server_id = self.jsonviewer.insert("", "end", text="Server name", tags=["tree_item", "server_label"])
        # save id of tree item so we can find it later
        server_name_id = self.jsonviewer.insert(server_id, "end", text=self.config_json["server"], tags=["tree_item", "server_value"])

        endpoints_id = self.jsonviewer.insert("", "end", text="Endpoints", tags=["tree_item", "endpoints"])

        for endpoint in self.config_json["endpoints"]:
            endpoint_id = self.jsonviewer.insert(endpoints_id, "end", text=endpoint["endpoint_path"], tags=["tree_item", "endpoint"])

            propogate_permissions_id = self.jsonviewer.insert(endpoint_id, "end", text="propogate_permissions", tags=["tree_item", "propogate_permissions_label"])
            propogate_permissions_value_id = self.jsonviewer.insert(propogate_permissions_id, "end", text=str(endpoint["propogate_permissions"]), tags=["tree_item", "propogate_permissions_value"])

            allowed_ip_addresses_id = self.jsonviewer.insert(endpoint_id, "end", text="allowed_ip_addresses", tags=["tree_item", "allowed_ip_addresses"])
            allowed_attributes_id = self.jsonviewer.insert(endpoint_id, "end", text="allowed_attributes", tags=["tree_item", "allowed_attributes"])

            for ip in endpoint["allowed_ip_addresses"]:
                ip_id = self.jsonviewer.insert(allowed_ip_addresses_id, "end", text=ip["ip"], tags=["tree_item", "ip"])
                permissions_id = self.jsonviewer.insert(ip_id, "end", text=ip["permissions"], tags=["tree_item", "ip_permissions"])

            for index, attribute_set in enumerate(endpoint["allowed_attributes"]):
                allowed_attribute_set_id = self.jsonviewer.insert(allowed_attributes_id, "end", text="Allowed attribute set " + str(index + 1), tags=["tree_item", "allowed_attributes_set"])

                attribute_requirements_id = self.jsonviewer.insert(allowed_attribute_set_id, "end", text="attribute_requirements", tags=["tree_item", "attribute_requirements"])
                for attribute in attribute_set["attribute_requirements"]:
                    attribute_id = self.jsonviewer.insert(attribute_requirements_id, "end", text=attribute["attribute"], tags=["tree_item", "attribute_name"])
                    value_id = self.jsonviewer.insert(attribute_id, "end", text=attribute["value"], tags=["tree_item", "attribute_value"])

                permissions_label_id = self.jsonviewer.insert(allowed_attribute_set_id, "end", text="permissions", tags=["tree_item", "attributes_permissions_label"])
                permissions_id = self.jsonviewer.insert(permissions_label_id, "end", text=attribute_set["permissions"], tags=["tree_item", "attributes_permissions_value"])

        self.add(self.jsonviewer)
        self.jsonviewer.tag_bind("tree_item", "<<TreeviewSelect>>", self.clear_edit_frame)
        self.jsonviewer.tag_bind("server_value", "<<TreeviewSelect>>", self.server_value_callback)
        self.jsonviewer.tag_bind("endpoints", "<<TreeviewSelect>>", self.endpoints_callback)
        self.jsonviewer.tag_bind("endpoint", "<<TreeviewSelect>>", self.endpoint_callback)
        self.jsonviewer.tag_bind("propogate_permissions_value", "<<TreeviewSelect>>", self.propogate_permissions_value_callback)
        self.jsonviewer.tag_bind("allowed_ip_addresses", "<<TreeviewSelect>>", self.allowed_ip_addresses_callback)
        self.jsonviewer.tag_bind("allowed_attributes", "<<TreeviewSelect>>", self.allowed_attributes_callback)
        self.jsonviewer.tag_bind("ip", "<<TreeviewSelect>>", self.ip_callback)
        self.jsonviewer.tag_bind("ip_permissions", "<<TreeviewSelect>>", self.ip_permissions_callback)
        self.jsonviewer.tag_bind("allowed_attributes_set", "<<TreeviewSelect>>", self.allowed_attributes_set_callback)
        self.jsonviewer.tag_bind("attribute_requirements", "<<TreeviewSelect>>", self.attribute_requirements_callback)
        self.jsonviewer.tag_bind("attribute_name", "<<TreeviewSelect>>", self.attribute_name_callback)
        self.jsonviewer.tag_bind("attribute_value", "<<TreeviewSelect>>", self.attribute_value_callback)
        self.jsonviewer.tag_bind("attributes_permissions_value", "<<TreeviewSelect>>", self.attributes_permissions_value_callback)

        self.editframe = tk.Frame(self)
        self.add(self.editframe)

        self.optionsframe = tk.LabelFrame(self.editframe, text="Choose part of the config to edit")
        self.optionsframe.pack(side=tk.TOP, expand=True, fill=tk.BOTH)

        self.quitButton = tk.Button(self.editframe, text='Quit', command=self.quit)
        self.quitButton.pack()

    # this is called before the other callbacks to clear the previous interface
    def clear_edit_frame(self, event):
        for widget in self.optionsframe.winfo_children():
            widget.destroy()

    def server_value_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Edit server name")

        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack()

        textbox = tk.Entry(holder_frame)
        textbox.pack(side=tk.LEFT)

        def update_servername():
            server = textbox.get()
            self.config_json["server"] = server

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.item(item, text=server)

        confirm_button = tk.Button(holder_frame, text="Update server name", command=update_servername)
        confirm_button.pack(side=tk.RIGHT)

    def endpoints_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Add new endpoint")

        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack()

        textbox = tk.Entry(holder_frame)
        textbox.pack(side=tk.LEFT)

        def add_endpoint():
            endpoint_path = textbox.get()
            new_endpoint = {
                "endpoint_path": endpoint_path,
                "allowed_attributes": [],
                "allowed_ip_addresses": [],
                "propogate_permissions": True
            }
            self.config_json["endpoints"].append(new_endpoint)

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            endpoint_id = self.jsonviewer.insert(item, "end", text=endpoint_path)
            self.endpoint_ids.append(endpoint_id)

        confirm_button = tk.Button(holder_frame, text="Add new endpoint", command=add_endpoint)
        confirm_button.pack(side=tk.RIGHT)

    def endpoint_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Edit " + self.jsonviewer.item(item, "text"))

        # need to be able to edit endpoint name, delete endpoint
        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack(side=tk.TOP)

        textbox = tk.Entry(holder_frame)
        textbox.pack(side=tk.LEFT)

        def update_path():
            new_path = textbox.get()
            self.config_json["endpoints"][self.jsonviewer.index(item)]["endpoint_path"] = new_path

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.item(item, text=new_path)

        confirm_button = tk.Button(holder_frame, text="Update endpoint path", command=update_path)
        confirm_button.pack(side=tk.RIGHT)

        def delete_endpoint():
            del self.config_json["endpoints"][self.jsonviewer.index(item)]

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.delete(item)

        delete_button = tk.Button(self.optionsframe, text="Delete this endpoint", command=delete_endpoint)
        delete_button.pack()

    def propogate_permissions_value_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Edit propogate_permissions")

        endpoint = self.jsonviewer.parent(self.jsonviewer.parent(item))

        state = tk.BooleanVar(value=self.config_json["endpoints"][self.jsonviewer.index(endpoint)]["propogate_permissions"])

        def update_propogate_permissions():
            self.config_json["endpoints"][self.jsonviewer.index(endpoint)]["propogate_permissions"] = state.get()

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.item(item, text=str(state.get()))

        checkbox = tk.Checkbutton(self.optionsframe, text="propogate_permissions", onvalue=True, offvalue=False, variable=state, command=update_propogate_permissions)
        checkbox.pack()

    def allowed_ip_addresses_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Add new IP address for endpoint " + self.jsonviewer.item(self.jsonviewer.parent(item))["text"])

        textbox = tk.Entry(self.optionsframe)
        textbox.pack(side=tk.TOP)

        read_state = tk.StringVar(value="")
        list_state = tk.StringVar(value="")
        write_state = tk.StringVar(value="")
        delete_state = tk.StringVar(value="")

        read_checkbox = tk.Checkbutton(self.optionsframe, text="Read", onvalue="r", offvalue="", variable=read_state)
        read_checkbox.pack()

        list_checkbox = tk.Checkbutton(self.optionsframe, text="List", onvalue="l", offvalue="", variable=list_state)
        list_checkbox.pack()

        write_checkbox = tk.Checkbutton(self.optionsframe, text="Write", onvalue="w", offvalue="", variable=write_state)
        write_checkbox.pack()

        delete_checkbox = tk.Checkbutton(self.optionsframe, text="Delete", onvalue="d", offvalue="", variable=delete_state)
        delete_checkbox.pack()

        def add_ip():
            ip_address = textbox.get()
            permissions = read_state.get() + list_state.get() + write_state.get() + delete_state.get()

            new_ip_address = {
                "ip": ip_address,
                "permissions": permissions,
            }

            self.config_json["endpoints"][self.jsonviewer.index(self.jsonviewer.parent(item))]["allowed_ip_addresses"].append(new_ip_address)

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            ip_id = self.jsonviewer.insert(item, "end", text=ip_address)
            permissions_id = self.jsonviewer.insert(ip_id, "end", text=permissions)
            self.ip_ids.append(ip_id)
            self.permissions_ids.append(permissions_id)

        confirm_button = tk.Button(self.optionsframe, text="Add new IP address", command=add_ip)
        confirm_button.pack()

    def allowed_attributes_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Add new set of allowed attributes for endpoint " + self.jsonviewer.item(self.jsonviewer.parent(item))["text"])

    def ip_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Edit IP address " + self.jsonviewer.item(item, "text"))

        # need to be able to edit IP address or delete
        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack(side=tk.TOP)

        textbox = tk.Entry(holder_frame)
        textbox.pack(side=tk.LEFT)

        def update_ip():
            new_ip = textbox.get()
            self.config_json["endpoints"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(item)))]["allowed_ip_addresses"][self.jsonviewer.index(item)]["ip"] = new_ip

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.item(item, text=new_ip)

        confirm_button = tk.Button(holder_frame, text="Update IP address", command=update_ip)
        confirm_button.pack(side=tk.RIGHT)

        def delete_ip():
            del self.config_json["endpoints"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(item)))]["allowed_ip_addresses"][self.jsonviewer.index(item)]

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.delete(item)

        delete_button = tk.Button(self.optionsframe, text="Delete this IP address", command=delete_ip)
        delete_button.pack()

    def ip_permissions_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Edit permissions")

        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack(side=tk.TOP)

        permissions = self.jsonviewer.item(item)["text"]

        if "r" in permissions:
            read_state = tk.StringVar(value="r")
        else:
            read_state = tk.StringVar(value="")

        if "l" in permissions:
            list_state = tk.StringVar(value="l")
        else:
            list_state = tk.StringVar(value="")

        if "w" in permissions:
            write_state = tk.StringVar(value="w")
        else:
            write_state = tk.StringVar(value="")

        if "d" in permissions:
            delete_state = tk.StringVar(value="d")
        else:
            delete_state = tk.StringVar(value="")

        def update_permissions():
            curr_permissions = read_state.get() + list_state.get() + write_state.get() + delete_state.get()
            # need to check if ip permissions or attribute permissions
            endpoint = self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(item)))
            self.config_json["endpoints"][self.jsonviewer.index(endpoint)]["allowed_ip_addresses"][self.jsonviewer.index(self.jsonviewer.parent(item))]["permissions"] = curr_permissions

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.item(item, text=curr_permissions)

        read_checkbox = tk.Checkbutton(holder_frame, text="Read", onvalue="r", offvalue="", variable=read_state, command=update_permissions)
        read_checkbox.pack()

        list_checkbox = tk.Checkbutton(holder_frame, text="List", onvalue="l", offvalue="", variable=list_state, command=update_permissions)
        list_checkbox.pack()

        write_checkbox = tk.Checkbutton(holder_frame, text="Write", onvalue="w", offvalue="", variable=write_state, command=update_permissions)
        write_checkbox.pack()

        delete_checkbox = tk.Checkbutton(holder_frame, text="Delete", onvalue="d", offvalue="", variable=delete_state, command=update_permissions)
        delete_checkbox.pack()

    def allowed_attributes_set_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Edit " + self.jsonviewer.item(item)["text"])

        def delete_attribute_set():
            del self.config_json["endpoints"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(item)))]["allowed_attributes"][self.jsonviewer.index(item)]

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.delete(item)

        delete_button = tk.Button(self.optionsframe, text="Delete this attribute set", command=delete_attribute_set)
        delete_button.pack(side=tk.TOP)

    def attribute_requirements_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Add new attribute")

        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack(side=tk.TOP)

        name_label = tk.Label(holder_frame)
        name_label.pack(side=tk.LEFT)

        name_textbox = tk.Entry(holder_frame)
        name_textbox.pack()

        value_label = tk.Label(holder_frame)
        value_label.pack()

        value_textbox = tk.Entry(holder_frame)
        value_textbox.pack()

        def add_attribute():
            new_name = name_textbox.get()
            new_value = value_textbox.get()
            new_attribute = {
                "attribute": new_name,
                "value": new_value
            }
            self.config_json["endpoints"][self.jsonviewer.index(eval("self.jsonviewer.parent(" * 3 + "item" + ")" * 3))]["allowed_attributes"][self.jsonviewer.index(self.jsonviewer.parent(item))]["attribute_requirements"].append(new_attribute)

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            attribute_id = self.jsonviewer.insert(item, "end", text=new_name, tags=["tree_item", "attribute_name"])
            self.jsonviewer.insert(attribute_id, "end", text=new_value, tags=["tree_item", "attribute_value"])

        confirm_button = tk.Button(holder_frame, text="Add attribute", command=add_attribute)
        confirm_button.pack(side=tk.RIGHT)

    def attribute_name_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Edit attribute name")

        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack(side=tk.TOP)

        textbox = tk.Entry(holder_frame)
        textbox.pack(side=tk.LEFT)

        def update_attribute():
            new_attribute = textbox.get()
            #self.config_json["endpoints"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(item)))))]["allowed_attributes"][self.jsonviewer.index(self.jsonviewer.parent(item))]["attribute_requirements"][self.jsonviewer.index(item)]["attribute"] = new_attribute
            self.config_json["endpoints"][self.jsonviewer.index(eval("self.jsonviewer.parent(" * 4 + "item" + ")" * 4))]["allowed_attributes"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(item)))]["attribute_requirements"][self.jsonviewer.index(item)]["attribute"] = new_attribute

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.item(item, text=new_attribute)

        confirm_button = tk.Button(holder_frame, text="Update attribute name", command=update_attribute)
        confirm_button.pack(side=tk.RIGHT)

        def delete_attribute():
            del self.config_json["endpoints"][self.jsonviewer.index(eval("self.jsonviewer.parent(" * 4 + "item" + ")" * 4))]["allowed_attributes"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(item)))]["attribute_requirements"][self.jsonviewer.index(item)]

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.delete(item)

        delete_button = tk.Button(self.optionsframe, text="Delete this attribute", command=delete_attribute)
        delete_button.pack()

    def attribute_value_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Edit value for attribute " + self.jsonviewer.item(self.jsonviewer.parent(item), "text"))

        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack(side=tk.TOP)

        textbox = tk.Entry(holder_frame)
        textbox.pack(side=tk.LEFT)

        def update_value():
            new_value = textbox.get()
            #self.config_json["endpoints"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(item))))))]["allowed_attributes"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(item)))]["attribute_requirements"][self.jsonviewer.index(self.jsonviewer.parent(item))]["value"] = new_value
            self.config_json["endpoints"][self.jsonviewer.index(eval("self.jsonviewer.parent(" * 5 + "item" + ")" * 5))]["allowed_attributes"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(item))))]["attribute_requirements"][self.jsonviewer.index(self.jsonviewer.parent(item))]["value"] = new_value

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.item(item, text=new_value)

        confirm_button = tk.Button(holder_frame, text="Update attribute value", command=update_value)
        confirm_button.pack(side=tk.RIGHT)

    def attributes_permissions_value_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Edit permissions")

        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack(side=tk.TOP)

        permissions = self.jsonviewer.item(item)["text"]

        if "r" in permissions:
            read_state = tk.StringVar(value="r")
        else:
            read_state = tk.StringVar(value="")

        if "l" in permissions:
            list_state = tk.StringVar(value="l")
        else:
            list_state = tk.StringVar(value="")

        if "w" in permissions:
            write_state = tk.StringVar(value="w")
        else:
            write_state = tk.StringVar(value="")

        if "d" in permissions:
            delete_state = tk.StringVar(value="d")
        else:
            delete_state = tk.StringVar(value="")

        def update_permissions():
            curr_permissions = read_state.get() + list_state.get() + write_state.get() + delete_state.get()
            # need to check if ip permissions or attribute permissions
            endpoint = self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(item))))
            self.config_json["endpoints"][self.jsonviewer.index(endpoint)]["allowed_attributes"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(item)))]["permissions"] = curr_permissions

            with open(args.file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.item(item, text=curr_permissions)

        read_checkbox = tk.Checkbutton(holder_frame, text="Read", onvalue="r", offvalue="", variable=read_state, command=update_permissions)
        read_checkbox.pack()

        list_checkbox = tk.Checkbutton(holder_frame, text="List", onvalue="l", offvalue="", variable=list_state, command=update_permissions)
        list_checkbox.pack()

        write_checkbox = tk.Checkbutton(holder_frame, text="Write", onvalue="w", offvalue="", variable=write_state, command=update_permissions)
        write_checkbox.pack()

        delete_checkbox = tk.Checkbutton(holder_frame, text="Delete", onvalue="d", offvalue="", variable=delete_state, command=update_permissions)
        delete_checkbox.pack()


# top level argument parser
parser = argparse.ArgumentParser()

# is this default okay or mark it as a required option?l
parser.add_argument("-f, --file", type=str, default="./ldap_auth.json", dest="file", help="Location of the JSON configuration file to act on. Defaults to ./ldap_auth.json")

if __name__ == "__main__":
    args = parser.parse_args()
    app = Application()
    app.mainloop()
