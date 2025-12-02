#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox, ttk
import easysnmp
import asyncio

class RSUConfigurationApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RSU Configuration")
        self.geometry("640x480")
        self.resizable(True, True)

        # Create notebook for tabs
        notebook = ttk.Notebook(self)
        notebook.pack(fill='both', expand=True, padx=12, pady=12)

        # Create tabs
        self.create_configuration_tab(notebook)
        self.create_immediate_forward_tab(notebook)
        self.create_received_message_forward_tab(notebook)
        self.create_store_and_repeat_tab(notebook)

    def create_configuration_tab(self, notebook):
        """Create the Configuration tab"""
        body = ttk.Frame(notebook, padding=12)
        notebook.add(body, text="Configuration")

        # Make grid resizable
        body.columnconfigure(1, weight=1)
        body.columnconfigure(2, weight=1)

        # SNMP session input fields
        r = 0
        ttk.Label(body, text="RSU IP Address:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.hostname_var = tk.StringVar(value="192.168.55.20")
        ttk.Entry(body, textvariable=self.hostname_var).grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
        r += 1
        ttk.Label(body, text="RSU SNMP Port:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.port_var = tk.IntVar(value=161)
        ttk.Entry(body, textvariable=self.port_var).grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
        r += 1
        ttk.Label(body, text="SNMPv3 Username:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.snmpv3_user_var = tk.StringVar(value="snmpuser")
        ttk.Entry(body, textvariable=self.snmpv3_user_var).grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
        r += 1
        ttk.Label(body, text="Security Level:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.security_level_var = tk.StringVar(value="authPriv")
        ttk.Combobox(body, textvariable=self.security_level_var, values=["noAuthNoPriv", "authNoPriv", "authPriv"]).grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
        r += 1
        ttk.Label(body, text="Auth Protocol:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.auth_protocol_var = tk.StringVar(value="SHA")
        ttk.Combobox(body, textvariable=self.auth_protocol_var, values=["MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"]).grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
        r += 1
        ttk.Label(body, text="Auth Password:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.auth_password_var = tk.StringVar(value="authpass")
        ttk.Entry(body, textvariable=self.auth_password_var, show="*").grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
        r += 1
        ttk.Label(body, text="Privacy Protocol:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.privacy_protocol_var = tk.StringVar(value="AES")
        ttk.Combobox(body, textvariable=self.privacy_protocol_var, values=["DES", "AES", "AES-128", "AES-192", "AES-256"]).grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
        r += 1
        ttk.Label(body, text="Privacy Password:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.privacy_password_var = tk.StringVar(value="privpass")
        ttk.Entry(body, textvariable=self.privacy_password_var, show="*").grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)

        # Initialize SNMP session
        self.session = easysnmp.Session(
            version=3,
            hostname=self.hostname_var.get(),
            remote_port=self.port_var.get(),
            security_username=self.snmpv3_user_var.get(),
            security_level=self.security_level_var.get(),
            auth_protocol=self.auth_protocol_var.get(),
            auth_password=self.auth_password_var.get(),
            privacy_protocol=self.privacy_protocol_var.get(),
            privacy_password=self.privacy_password_var.get()
        )

        # Buttons
        r += 1
        button_frame = ttk.Frame(body)
        button_frame.grid(row=r, column=0, columnspan=4, sticky='ew', padx=6, pady=6)
        ttk.Button(button_frame, text="Walk RSU MIBs", command=self.walk_mibs).pack(side='left', padx=6)
        ttk.Button(button_frame, text="Quit", command=self.quit).pack(side='right', padx=6)

        # Label + read-only text widget to show results
        r += 1
        results_frame = ttk.LabelFrame(body, text="Results", padding=8)
        results_frame.grid(row=r, column=0, columnspan=4, sticky='nsew', padx=6, pady=6)
        body.rowconfigure(r, weight=1)

        ttk.Label(results_frame).pack(anchor='w')
        self.results_text = tk.Text(results_frame, height=6, wrap='word')
        self.results_text.pack(fill='both', expand=True)
        self.results_text.configure(state='disabled')

    def create_immediate_forward_tab(self, notebook):
        """Create the Immediate Forward tab"""
        ifm_tab = ttk.Frame(notebook, padding=12)
        notebook.add(ifm_tab, text="Immediate Forward")

        # Layout config
        ifm_tab.columnconfigure(0, weight=1)
        ifm_tab.rowconfigure(1, weight=1)

        # Controls row
        controls = ttk.Frame(ifm_tab)
        controls.grid(row=0, column=0, sticky='ew', padx=6, pady=6)

        # Container for IFM rows
        rows_frame = ttk.Frame(ifm_tab)
        rows_frame.grid(row=1, column=0, sticky='nsew', padx=6, pady=6)
        rows_frame.columnconfigure(0, weight=1)

        def destroy_ifm_entry(idx: int, entry_widget: ttk.Entry, button_widget: ttk.Button) -> None:
            """Destroy IFM entry for the given index and update given UI row."""
            delete_ifm_oid = f"1.3.6.1.4.1.1206.4.2.18.4.2.1.5.{idx}"
            self.destroy_entry(delete_ifm_oid, entry_widget, button_widget)

        def get_ifm_info() -> None:
            """Fetch IFM info and render each result as a read-only row with a Destroy button."""
            # Clear previous rows
            for child in rows_frame.winfo_children():
                child.destroy()

            current_row = 0
            for i in range(1, 7):
                get_oid = f"1.3.6.1.4.1.1206.4.2.18.4.2.1.2.{i}"
                try:
                    ifm_info = self.session.get(get_oid)
                    text = f"IFM Index {i}: {ifm_info}"
                    var = tk.StringVar(value=text)
                    entry = ttk.Entry(rows_frame, textvariable=var, state='readonly')
                    entry._var = var  # type: ignore  # Keep StringVar alive
                    entry.grid(row=current_row, column=0, sticky='ew', padx=4, pady=2)
                    btn = ttk.Button(rows_frame, text="Destroy")
                    btn.grid(row=current_row, column=1, sticky='w', padx=4, pady=2)
                    btn.configure(command=lambda idx=i, e=entry, b=btn: destroy_ifm_entry(idx, e, b))
                    current_row += 1
                except easysnmp.EasySNMPError as e:
                    # Show an error row for this index
                    err_text = f"IFM Index {i}: error retrieving info"
                    var = tk.StringVar(value=err_text)
                    entry = ttk.Entry(rows_frame, textvariable=var, state='readonly')
                    entry._var = var  # type: ignore  # Keep StringVar alive
                    entry.grid(row=current_row, column=0, sticky='ew', padx=4, pady=2)
                    btn = ttk.Button(rows_frame, text="Destroy", state='disabled')
                    btn.grid(row=current_row, column=1, sticky='w', padx=4, pady=2)
                    current_row += 1
                    messagebox.showerror("SNMP Error", str(e))

        def set_ifm_info() -> None:
            # todo
            pass

        ttk.Button(controls, text="Get IFM Info", command=get_ifm_info).pack(side='left', padx=6)

    def create_received_message_forward_tab(self, notebook):
        """Create the Received Message Forward tab"""
        rmf_tab = ttk.Frame(notebook, padding=12)
        notebook.add(rmf_tab, text="Received Message Forward")

        # Layout config
        rmf_tab.columnconfigure(0, weight=1)
        rmf_tab.rowconfigure(1, weight=1)

        # Controls row
        controls = ttk.Frame(rmf_tab)
        controls.grid(row=0, column=0, sticky='ew', padx=6, pady=6)

        # Container for RMF rows
        rows_frame = ttk.Frame(rmf_tab)
        rows_frame.grid(row=1, column=0, sticky='nsew', padx=6, pady=6)
        rows_frame.columnconfigure(0, weight=1)

        def destroy_rfm_entry(idx: int, entry_widget: ttk.Entry, button_widget: ttk.Button) -> None:
            """Destroy RFM entry for the given index and update given UI row."""
            delete_ifm_oid = f"1.3.6.1.4.1.1206.4.2.18.5.2.1.10.{idx}"
            self.destroy_entry(delete_ifm_oid, entry_widget, button_widget)

        def get_rfm_info() -> None:
            """Fetch RFM info and render each result as a read-only row with a Destroy button."""
            # Clear previous rows
            for child in rows_frame.winfo_children():
                child.destroy()

            current_row = 0
            for i in range(1, 7):
                for j in range(2, 5):
                    get_oid = f"1.3.6.1.4.1.1206.4.2.18.5.2.1.{j}.{i}"
                    try:
                        rfm_info = self.session.get(get_oid)
                        text = f"RFM Index {j}.{i}: {rfm_info}"
                        var = tk.StringVar(value=text)
                        entry = ttk.Entry(rows_frame, textvariable=var, state='readonly')
                        entry._var = var  # type: ignore  # Keep StringVar alive
                        entry.grid(row=current_row, column=0, sticky='ew', padx=4, pady=2)
                        btn = ttk.Button(rows_frame, text="Destroy")
                        btn.grid(row=current_row, column=1, sticky='w', padx=4, pady=2)
                        btn.configure(command=lambda idx=i, e=entry, b=btn: destroy_rfm_entry(idx, e, b))
                        current_row += 1
                    except easysnmp.EasySNMPError as e:
                        # Show an error row for this index
                        err_text = f"RFM Index {i}: error retrieving info"
                        var = tk.StringVar(value=err_text)
                        entry = ttk.Entry(rows_frame, textvariable=var, state='readonly')
                        entry._var = var  # type: ignore  # Keep StringVar alive
                        entry.grid(row=current_row, column=0, sticky='ew', padx=4, pady=2)
                        btn = ttk.Button(rows_frame, text="Destroy", state='disabled')
                        btn.grid(row=current_row, column=1, sticky='w', padx=4, pady=2)
                        current_row += 1
                        messagebox.showerror("SNMP Error", str(e))

        def set_rfm_info() -> None:
            # todo
            pass

        ttk.Button(controls, text="Get RFM Info", command=get_rfm_info).pack(side='left', padx=6)

    def create_store_and_repeat_tab(self, notebook):
        """Create the Store-and-Repeat tab"""
        srm_tab = ttk.Frame(notebook, padding=12)
        notebook.add(srm_tab, text="Store-and-Repeat")

        # Layout config
        srm_tab.columnconfigure(0, weight=1)
        srm_tab.rowconfigure(1, weight=1)

        # Controls row
        controls = ttk.Frame(srm_tab)
        controls.grid(row=0, column=0, sticky='ew', padx=6, pady=6)

        # Container for SRM rows
        rows_frame = ttk.Frame(srm_tab)
        rows_frame.grid(row=1, column=0, sticky='nsew', padx=6, pady=6)
        rows_frame.columnconfigure(0, weight=1)

        def destroy_srm_entry(idx: int, entry_widget: ttk.Entry, button_widget: ttk.Button) -> None:
            """Destroy SRM entry for the given index and update given UI row."""
            delete_ifm_oid = f"1.3.6.1.4.1.1206.4.2.18.3.2.1.9.{idx}"
            self.destroy_entry(delete_ifm_oid, entry_widget, button_widget)

        def get_srm_info() -> None:
            """Fetch SRM info and render each result as a read-only row with a Destroy button."""
            # Clear previous rows
            for child in rows_frame.winfo_children():
                child.destroy()

            current_row = 0
            for i in range(1, 7):
                for j in range(2, 8, 5): # get entries 2 and 7 (psid and payload)
                    get_oid = f"1.3.6.1.4.1.1206.4.2.18.3.2.1.{j}.{i}"
                    try:
                        srm_info = self.session.get(get_oid)
                        text = f"SRM Index {j}.{i}: {srm_info}"
                        var = tk.StringVar(value=text)
                        entry = ttk.Entry(rows_frame, textvariable=var, state='readonly')
                        entry._var = var  # type: ignore  # Keep StringVar alive
                        entry.grid(row=current_row, column=0, sticky='ew', padx=4, pady=2)
                        btn = ttk.Button(rows_frame, text="Destroy")
                        btn.grid(row=current_row, column=1, sticky='w', padx=4, pady=2)
                        btn.configure(command=lambda idx=i, e=entry, b=btn: destroy_srm_entry(idx, e, b))
                        current_row += 1
                    except easysnmp.EasySNMPError as e:
                        # Show an error row for this index
                        err_text = f"SRM Index {i}: error retrieving info"
                        var = tk.StringVar(value=err_text)
                        entry = ttk.Entry(rows_frame, textvariable=var, state='readonly')
                        entry._var = var  # type: ignore  # Keep StringVar alive
                        entry.grid(row=current_row, column=0, sticky='ew', padx=4, pady=2)
                        btn = ttk.Button(rows_frame, text="Destroy", state='disabled')
                        btn.grid(row=current_row, column=1, sticky='w', padx=4, pady=2)
                        current_row += 1
                        messagebox.showerror("SNMP Error", str(e))

        def set_srm_info() -> None:
            # todo
            pass

        ttk.Button(controls, text="Get SRM Info", command=get_srm_info).pack(side='left', padx=6)

    # Methods
    def walk_mibs(self):
        self.results_text.configure(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Walking RSU MIBs...\n")
        self.results_text.configure(state='disabled')
        self.update_idletasks()

        try:
            oid = '1.3.6.1.4.1.1206.4.2.18'
            results = self.session.walk(oid)
            self.results_text.configure(state='normal')
            for item in results:
                self.results_text.insert(tk.END, f"{item.oid} = {item.value}\n")
            self.results_text.configure(state='disabled')
        except easysnmp.EasySNMPError as e:
            messagebox.showerror("SNMP Error", str(e))
            self.results_text.configure(state='normal')
            self.results_text.insert(tk.END, "Error walking MIBs.\n")
            self.results_text.configure(state='disabled')

    def destroy_entry(self, delete_oid: str, entry_widget: ttk.Entry, button_widget: ttk.Button) -> None:
            """Destroy entry for the given oid and update given UI row."""
            try:
                self.session.set(delete_oid, 6)  # 6 = destroy
                # Remove the row from UI
                entry_widget.destroy()
                button_widget.destroy()
            except easysnmp.EasySNMPError as e:
                messagebox.showerror("SNMP Error", str(e))

def main():
    root = RSUConfigurationApp()
    root.mainloop()

if __name__ == "__main__":
    main()
