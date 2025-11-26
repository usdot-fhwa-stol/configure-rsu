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

        # Label + read-only text widget to show some results
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
        body = ttk.Frame(notebook, padding=12)
        notebook.add(body, text="Immediate Forward")

        r = 0
        

    def create_received_message_forward_tab(self, notebook):
        """Create the Received Message Forward tab"""
        body = ttk.Frame(notebook, padding=12)
        notebook.add(body, text="Received Message Forward")

    def create_store_and_repeat_tab(self, notebook):
        """Create the Store-and-Repeat tab"""
        body = ttk.Frame(notebook, padding=12)
        notebook.add(body, text="Store-and-Repeat")

    # Methods
    def walk_mibs(self):
        self.results_text.configure(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Walking RSU MIBs...\n")
        self.results_text.configure(state='disabled')
        self.update_idletasks()

        try:
            # Example OID for demonstration; replace with actual RSU MIB OIDs
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


def main():
    root = RSUConfigurationApp()
    root.mainloop()

if __name__ == "__main__":
    main()
