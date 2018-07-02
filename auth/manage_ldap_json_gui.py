#!/usr/bin/env python
from __future__ import print_function, unicode_literals
import Tkinter as tk
import tkFileDialog
import ttk
import json


class Application(tk.PanedWindow):
    # different interfaces needed for different types of node, keep track of IDs here

    def __init__(self, master=None):
        tk.PanedWindow.__init__(self, master)
        self.master.title("Edit JSON config")
        self.master.geometry("800x600")

        self.pack(fill=tk.BOTH, expand=1)
        self.init_widgets()
        self.master.config(menu=self.menubar)
        self.config_file = ""

    def choose_config_file(self):
        with tkFileDialog.askopenfile(parent=self, mode="r", title="Choose a JSON config file", defaultextension='.json', filetypes=[("JSON", "*.json"), ("All Files", "*.*")]) as f:
            self.config_file = f.name
            self.config_json = json.load(f)
            self.populate_tree()

    def new_config_file(self):
        template = {
            "server": "",
            "endpoints": []
        }
        with tkFileDialog.asksaveasfile(parent=self, mode="w", title="Choose a location to create JSON config file", defaultextension='.json', filetypes=[("JSON", "*.json"), ("All Files", "*.*")]) as f:
            json.dump(template, f)
            self.config_file = f.name
            self.config_json = template
            self.populate_tree()

    def save_config_file(self):
        template = {
            "server": "",
            "endpoints": []
        }
        for i in self.jsonviewer.get_children():
            if self.jsonviewer.item(i)["text"] == "Server Name":
                server_name_id = self.jsonviewer.get_children(i)[0]
                template["server"] = self.jsonviewer.item(server_name_id)["text"]
            if self.jsonviewer.item(i)["text"] == "Endpoints":
                endpoints_id = i

        # iterate over endpoints
        for endpoint_id in self.jsonviewer.get_children(endpoints_id):
            endpoint = {
                "endpoint_path": "",
                "allowed_attributes": [],
                "allowed_ip_addresses": [],
                "propogate_permissions": True,
            }
            endpoint["endpoint_path"] = self.jsonviewer.item(endpoint_id)["text"]
            for i in self.jsonviewer.get_children(endpoint_id):
                if self.jsonviewer.item(i)["text"] == "propogate_permissions":
                    propogate_permissions_value_id = self.jsonviewer.get_children(i)[0]
                    endpoint["propogate_permissions"] = bool(self.jsonviewer.item(propogate_permissions_value_id)["text"])

                if self.jsonviewer.item(i)["text"] == "allowed_ip_addresses":
                    for ip_id in self.jsonviewer.get_children(i):
                        ip_entry = {
                            "ip": "",
                            "permissions": ""
                        }
                        ip_entry["ip"] = self.jsonviewer.item(ip_id)["text"]
                        ip_entry["permissions"] = self.jsonviewer.item(self.jsonviewer.get_children(ip_id)[0])["text"]
                        endpoint["allowed_ip_addresses"].append(ip_entry)

                if self.jsonviewer.item(i)["text"] == "allowed_attributes":
                    for attribute_set_id in self.jsonviewer.get_children(i):
                        attribute_set = {
                            "attribute_requirements": [],
                            "permissions": ""
                        }
                        for ii in self.jsonviewer.get_children(attribute_set_id):
                            if self.jsonviewer.item(ii)["text"] == "attribute_requirements":
                                for attribute_id in self.jsonviewer.get_children(ii):
                                    attribute = {
                                        "attribute": "",
                                        "value": ""
                                    }
                                    attribute["attribute"] = self.jsonviewer.item(attribute_id)["text"]
                                    attribute["value"] = self.jsonviewer.item(self.jsonviewer.get_children(attribute_id)[0])["text"]
                                    attribute_set["attribute_requirements"].append(attribute)

                            if self.jsonviewer.item(ii)["text"] == "permissions":
                                attribute_set["permissions"] = self.jsonviewer.item(self.jsonviewer.get_children(ii)[0])["text"]

                        endpoint["allowed_attributes"].append(attribute_set)

            template["endpoints"].append(endpoint)

        with tkFileDialog.asksaveasfile(parent=self, initialfile=self.config_file, mode="w", title="Choose a location to save JSON config file", defaultextension='.json', filetypes=[("JSON", "*.json"), ("All Files", "*.*")]) as f:
            json.dump(template, f)
            self.config_file = f.name
            self.config_json = template
            self.populate_tree()

    def help_dialog(self):
        help_popup = tk.Toplevel(master=self, bd=1, relief="raised", height=1500)
        help_popup.title("Help")
        help_text = tk.Text(help_popup, font=("Helvetica", 16))
        help_text.configure(font=("Times New Roman", 16))
        help_text.insert(tk.INSERT, "Click on New or Open in the file menu to load a file.\n\n")
        help_text.insert(tk.INSERT, "Once a file is loaded, the left panel will display a tree structure "
                                    "representing the structure of the underlying config file. The right panel "
                                    "will display different controls depending on current selected item and the "
                                    "functions one can perform on that item.\n\n")
        help_text.insert(tk.INSERT, "Server Name:", ("bold"))
        help_text.insert(tk.INSERT, " the child of this item is name of the LDAP server, and click the name "
                                    "of the server to edit it\n\n")
        help_text.insert(tk.INSERT, "Endpoints:", ("bold"))
        help_text.insert(tk.INSERT, " lists all the endpoint paths being protected by the config file, and "
                                    "new endpoints can be added here by supplying the path of the endpoint\n\n")
        help_text.insert(tk.INSERT, "Individual endpoint paths (e.g. /foo):", ("bold"))
        help_text.insert(tk.INSERT, " endpoint paths can be clicked on to edit "
                                    "the path or to delete the endpoint. It's children specify the allowed IP address "
                                    "and attributes that can be used to access this endpoint\n\n")
        help_text.insert(tk.INSERT, "propogate_permissions:", ("bold"))
        help_text.insert(tk.INSERT, " each endpoint has a propogate_permissions item, which can "
                                    "edited to be True or False. True means that any subpaths will have the same access "
                                    "controls applied to them, whereas False means that the access controls only apply "
                                    "to the current path and not any of it's subpaths. One example where False is "
                                    "useful to give the top level read permissions so that any user can see bucket names "
                                    "and not to give the user read permissions for the entire federation\n\n")
        help_text.insert(tk.INSERT, "allowed_ip_addresses:", ("bold"))
        help_text.insert(tk.INSERT, " contains all the ip addresses that have some sort of access control. Clicking "
                                    "on this allows you to add a new ip address and specify its permissions\n\n")
        help_text.insert(tk.INSERT, "Infividual IP addresses (e.g. 127.0.0.1):", ("bold"))
        help_text.insert(tk.INSERT, " you can edit the IP address or delete it by clicking on the IP address itself. Its "
                                    "child contains the permissions which can be modified using checkboxes\n\n")
        help_text.insert(tk.INSERT, "allowed_attributes:", ("bold"))
        help_text.insert(tk.INSERT, " contains all the attribute sets that have some sort of access control. Clicking "
                                    " on this allows you to add a new attribute set and specify its permissions\n\n")
        help_text.insert(tk.INSERT, "Allowed attribute sets:", ("bold"))
        help_text.insert(tk.INSERT, " sets of attributes that all have the same permissions. Satisfying any attribute "
                                    "set will grant the relevant permissions (logical OR), but every attribute in the "
                                    "attribute_requirements list must be satisfied (logical AND). You can delete the "
                                    "whole attribute set from the right hand side controls.\n\n")
        help_text.insert(tk.INSERT, "attribute_requirements:", ("bold"))
        help_text.insert(tk.INSERT, " contains a list of every attribute-value pair that needs to be satisfied in order "
                                    "to grant the corresponding permissions. New attribute-value pairs can be added here\n\n")
        help_text.insert(tk.INSERT, "Attribute name (e.g. email):", ("bold"))
        help_text.insert(tk.INSERT, " the name of the attribute. The attribute name can be edited or deleted here\n\n")
        help_text.insert(tk.INSERT, "Attribute value (e.g. example@stfc.ac.uk):", ("bold"))
        help_text.insert(tk.INSERT, " the value of the parent attribute to match the client against. You can change the value here\n\n")
        help_text.insert(tk.INSERT, "permissions:", ("bold"))
        help_text.insert(tk.INSERT, " the permissions that satisfying the attribute_requirements grants the user. "
                                    "Checkboxes are used to modify the permissions.\n\n")

        help_text.tag_configure("bold", font=("Arial", 12, "bold"), underline=1)
        height = int(float(help_text.index(tk.END)))
        help_text.configure(state=tk.DISABLED, height=height + 20, width=100)
        help_text.pack()

    def populate_tree(self):
        # clear tree of any old items that may be in the tree
        for i in self.jsonviewer.get_children():
            self.jsonviewer.delete(i)

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

    def init_widgets(self):
        self.jsonviewer = ttk.Treeview(selectmode="browse")
        self.add(self.jsonviewer, width=300)

        self.editframe = tk.Frame(self)
        self.add(self.editframe)

        self.optionsframe = tk.LabelFrame(self.editframe, text="Choose part of the config to edit")
        self.optionsframe.pack(expand=True, fill=tk.BOTH)

        self.menubar = tk.Menu(self)

        filemenu = tk.Menu(self.menubar, tearoff=0)
        filemenu.add_command(label="New", command=self.new_config_file)
        filemenu.add_command(label="Open", command=self.choose_config_file)
        filemenu.add_command(label="Save", command=self.save_config_file)
        filemenu.add_separator()
        filemenu.add_command(label="Quit", command=self.quit)
        self.menubar.add_cascade(label="File", menu=filemenu)

        self.menubar.add_command(label="Help", command=self.help_dialog)

    # this is called before the other callbacks to clear the previous interface
    def clear_edit_frame(self, event):
        for widget in self.optionsframe.winfo_children():
            widget.destroy()

    def server_value_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Edit server name")

        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack()

        textbox = tk.Entry(holder_frame, bg="white")
        textbox.pack(side=tk.LEFT)

        def update_servername():
            server = textbox.get()
            self.config_json["server"] = server

            with open(self.config_file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.item(item, text=server)

        confirm_button = tk.Button(holder_frame, text="Update server name", command=update_servername)
        confirm_button.pack(side=tk.RIGHT)

    def endpoints_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Add new endpoint")

        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack()

        textbox = tk.Entry(holder_frame, bg="white")
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

            with open(self.config_file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.insert(item, "end", text=endpoint_path)
            propogate_permissions_id = self.jsonviewer.insert(endpoint_id, "end", text="propogate_permissions", tags=["tree_item", "propogate_permissions_label"])
            self.jsonviewer.insert(propogate_permissions_id, "end", text=str(endpoint["propogate_permissions"]), tags=["tree_item", "propogate_permissions_value"])

            self.jsonviewer.insert(endpoint_id, "end", text="allowed_ip_addresses", tags=["tree_item", "allowed_ip_addresses"])
            self.jsonviewer.insert(endpoint_id, "end", text="allowed_attributes", tags=["tree_item", "allowed_attributes"])

        confirm_button = tk.Button(holder_frame, text="Add new endpoint", command=add_endpoint)
        confirm_button.pack(side=tk.RIGHT)

    def endpoint_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Edit " + self.jsonviewer.item(item, "text"))

        # need to be able to edit endpoint name, delete endpoint
        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack(side=tk.TOP)

        textbox = tk.Entry(holder_frame, bg="white")
        textbox.pack(side=tk.LEFT)

        def update_path():
            new_path = textbox.get()
            self.config_json["endpoints"][self.jsonviewer.index(item)]["endpoint_path"] = new_path

            with open(self.config_file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.item(item, text=new_path)

        confirm_button = tk.Button(holder_frame, text="Update endpoint path", command=update_path)
        confirm_button.pack(side=tk.RIGHT)

        def delete_endpoint():
            del self.config_json["endpoints"][self.jsonviewer.index(item)]

            with open(self.config_file, "w") as f:
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

            with open(self.config_file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.item(item, text=str(state.get()))

        checkbox = tk.Checkbutton(self.optionsframe, text="propogate_permissions", onvalue=True, offvalue=False, variable=state, command=update_propogate_permissions)
        checkbox.pack()

    def allowed_ip_addresses_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Add new IP address for endpoint " + self.jsonviewer.item(self.jsonviewer.parent(item))["text"])

        textbox = tk.Entry(self.optionsframe, bg="white")
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

            with open(self.config_file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            ip_id = self.jsonviewer.insert(item, "end", text=ip_address)
            permissions_id = self.jsonviewer.insert(ip_id, "end", text=permissions)

        confirm_button = tk.Button(self.optionsframe, text="Add new IP address", command=add_ip)
        confirm_button.pack()

    def allowed_attributes_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Add new set of allowed attributes for endpoint " + self.jsonviewer.item(self.jsonviewer.parent(item))["text"])

        attributes_frame = tk.LabelFrame(self.optionsframe, text="attribute_requirements")
        attributes_frame.pack(side=tk.TOP)

        def add_attribute_fields():
            holder_frame = tk.Frame(attributes_frame)
            holder_frame.pack(side=tk.TOP)

            name_label = tk.Label(holder_frame, text="Attribute name")
            name_label.pack(side=tk.LEFT)

            name_textbox = tk.Entry(holder_frame, name="attribute_name", bg="white")
            name_textbox.pack(side=tk.LEFT)

            value_label = tk.Label(holder_frame, text="Attribute value")
            value_label.pack(side=tk.LEFT)

            value_textbox = tk.Entry(holder_frame, name="attribute_value", bg="white")
            value_textbox.pack(side=tk.LEFT)

            def remove_attribute():
                value_textbox.destroy()
                value_label.destroy()
                name_textbox.destroy()
                name_label.destroy()
                remove_button.destroy()
                holder_frame.destroy()

            remove_button = tk.Button(holder_frame, text="X", command=remove_attribute)
            remove_button.pack(side=tk.RIGHT)

        add_attribute_button = tk.Button(attributes_frame, text="Add attribute", command=add_attribute_fields)
        add_attribute_button.pack(side=tk.BOTTOM)

        permissions_frame = tk.LabelFrame(self.optionsframe, text="permissions")
        permissions_frame.pack()

        read_state = tk.StringVar(value="")
        list_state = tk.StringVar(value="")
        write_state = tk.StringVar(value="")
        delete_state = tk.StringVar(value="")

        read_checkbox = tk.Checkbutton(permissions_frame, text="Read", onvalue="r", offvalue="", variable=read_state)
        read_checkbox.pack(side=tk.LEFT)

        list_checkbox = tk.Checkbutton(permissions_frame, text="List", onvalue="l", offvalue="", variable=list_state)
        list_checkbox.pack(side=tk.LEFT)

        write_checkbox = tk.Checkbutton(permissions_frame, text="Write", onvalue="w", offvalue="", variable=write_state)
        write_checkbox.pack(side=tk.LEFT)

        delete_checkbox = tk.Checkbutton(permissions_frame, text="Delete", onvalue="d", offvalue="", variable=delete_state)
        delete_checkbox.pack(side=tk.LEFT)

        def add_attribute_set():
            permissions = read_state.get() + list_state.get() + write_state.get() + delete_state.get()

            attribute_set = {
                "attribute_requirements": [],
                "permissions": permissions
            }

            for holder_frames in attributes_frame.winfo_children():
                # need to skip the confirm button
                if isinstance(holder_frames, tk.Button):
                    continue

                attribute = {
                    "attribute": "",
                    "value": ""
                }
                for widget in holder_frames.winfo_children():
                    if "attribute_name" in str(widget):
                        attribute["attribute"] = widget.get()
                    if "attribute_value" in str(widget):
                        attribute["value"] = widget.get()

                attribute_set["attribute_requirements"].append(attribute)

            self.config_json["endpoints"][self.jsonviewer.index(self.jsonviewer.parent(item))]["allowed_attributes"].append(attribute_set)

            with open(self.config_file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            allowed_attribute_set_id = self.jsonviewer.insert(item, "end", text="Allowed attribute set " + str(len(self.jsonviewer.get_children(item)) + 1), tags=["tree_item", "allowed_attributes_set"])

            attribute_requirements_id = self.jsonviewer.insert(allowed_attribute_set_id, "end", text="attribute_requirements", tags=["tree_item", "attribute_requirements"])
            for attribute in attribute_set["attribute_requirements"]:
                attribute_id = self.jsonviewer.insert(attribute_requirements_id, "end", text=attribute["attribute"], tags=["tree_item", "attribute_name"])
                value_id = self.jsonviewer.insert(attribute_id, "end", text=attribute["value"], tags=["tree_item", "attribute_value"])

            permissions_label_id = self.jsonviewer.insert(allowed_attribute_set_id, "end", text="permissions", tags=["tree_item", "attributes_permissions_label"])
            permissions_id = self.jsonviewer.insert(permissions_label_id, "end", text=attribute_set["permissions"], tags=["tree_item", "attributes_permissions_value"])

        confirm_button = tk.Button(self.optionsframe, text="Add allowed attribute set", command=add_attribute_set)
        confirm_button.pack()

    def ip_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Edit IP address " + self.jsonviewer.item(item, "text"))

        # need to be able to edit IP address or delete
        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack(side=tk.TOP)

        textbox = tk.Entry(holder_frame, bg="white")
        textbox.pack(side=tk.LEFT)

        def update_ip():
            new_ip = textbox.get()
            self.config_json["endpoints"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(item)))]["allowed_ip_addresses"][self.jsonviewer.index(item)]["ip"] = new_ip

            with open(self.config_file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.item(item, text=new_ip)

        confirm_button = tk.Button(holder_frame, text="Update IP address", command=update_ip)
        confirm_button.pack(side=tk.RIGHT)

        def delete_ip():
            del self.config_json["endpoints"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(item)))]["allowed_ip_addresses"][self.jsonviewer.index(item)]

            with open(self.config_file, "w") as f:
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

            with open(self.config_file, "w") as f:
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

            with open(self.config_file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.delete(item)

        delete_button = tk.Button(self.optionsframe, text="Delete this attribute set", command=delete_attribute_set)
        delete_button.pack(side=tk.TOP)

    def attribute_requirements_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Add new attribute")

        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack(side=tk.TOP)

        name_label = tk.Label(holder_frame, text="Attribute name")
        name_label.pack(side=tk.LEFT)

        name_textbox = tk.Entry(holder_frame, bg="white")
        name_textbox.pack(side=tk.LEFT)

        value_label = tk.Label(holder_frame, text="Attribute value")
        value_label.pack(side=tk.LEFT)

        value_textbox = tk.Entry(holder_frame, bg="white")
        value_textbox.pack(side=tk.LEFT)

        def add_attribute():
            new_name = name_textbox.get()
            new_value = value_textbox.get()
            new_attribute = {
                "attribute": new_name,
                "value": new_value
            }
            self.config_json["endpoints"][self.jsonviewer.index(eval("self.jsonviewer.parent(" * 3 + "item" + ")" * 3))]["allowed_attributes"][self.jsonviewer.index(self.jsonviewer.parent(item))]["attribute_requirements"].append(new_attribute)

            with open(self.config_file, "w") as f:
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

        textbox = tk.Entry(holder_frame, bg="white")
        textbox.pack(side=tk.LEFT)

        def update_attribute():
            new_attribute = textbox.get()
            #self.config_json["endpoints"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(item)))))]["allowed_attributes"][self.jsonviewer.index(self.jsonviewer.parent(item))]["attribute_requirements"][self.jsonviewer.index(item)]["attribute"] = new_attribute
            self.config_json["endpoints"][self.jsonviewer.index(eval("self.jsonviewer.parent(" * 4 + "item" + ")" * 4))]["allowed_attributes"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(item)))]["attribute_requirements"][self.jsonviewer.index(item)]["attribute"] = new_attribute

            with open(self.config_file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.item(item, text=new_attribute)

        confirm_button = tk.Button(holder_frame, text="Update attribute name", command=update_attribute)
        confirm_button.pack(side=tk.RIGHT)

        def delete_attribute():
            del self.config_json["endpoints"][self.jsonviewer.index(eval("self.jsonviewer.parent(" * 4 + "item" + ")" * 4))]["allowed_attributes"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(item)))]["attribute_requirements"][self.jsonviewer.index(item)]

            with open(self.config_file, "w") as f:
                json.dump(self.config_json, f, indent=4)

            self.jsonviewer.delete(item)

        delete_button = tk.Button(self.optionsframe, text="Delete this attribute", command=delete_attribute)
        delete_button.pack()

    def attribute_value_callback(self, event):
        item = self.jsonviewer.focus()
        self.optionsframe.config(text="Edit value for attribute " + self.jsonviewer.item(self.jsonviewer.parent(item), "text"))

        holder_frame = tk.Frame(self.optionsframe)
        holder_frame.pack(side=tk.TOP)

        textbox = tk.Entry(holder_frame, bg="white")
        textbox.pack(side=tk.LEFT)

        def update_value():
            new_value = textbox.get()
            #self.config_json["endpoints"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(item))))))]["allowed_attributes"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(item)))]["attribute_requirements"][self.jsonviewer.index(self.jsonviewer.parent(item))]["value"] = new_value
            self.config_json["endpoints"][self.jsonviewer.index(eval("self.jsonviewer.parent(" * 5 + "item" + ")" * 5))]["allowed_attributes"][self.jsonviewer.index(self.jsonviewer.parent(self.jsonviewer.parent(self.jsonviewer.parent(item))))]["attribute_requirements"][self.jsonviewer.index(self.jsonviewer.parent(item))]["value"] = new_value

            with open(self.config_file, "w") as f:
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

            with open(self.config_file, "w") as f:
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


if __name__ == "__main__":
    root = tk.Tk()
    app = Application(root)
    app.mainloop()
