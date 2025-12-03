#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox, ttk
import easysnmp
import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

# Load SNMP credentials from environment variables
SNMP_USER = os.getenv('SNMP_USER')
AUTH_PASSWORD = os.getenv('AUTH_PASSWORD')
PRIV_PASSWORD = os.getenv('PRIV_PASSWORD')

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
        self.snmpv3_user_var = tk.StringVar(value=SNMP_USER if SNMP_USER else "snmpuser")
        ttk.Entry(body, textvariable=self.snmpv3_user_var).grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
        r += 1
        ttk.Label(body, text="Security Level:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.security_level_var = tk.StringVar(value="authPriv")
        ttk.Combobox(body, textvariable=self.security_level_var, values=["noAuthNoPriv", "authNoPriv", "authPriv"]).grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
        r += 1
        ttk.Label(body, text="Auth Protocol:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.auth_protocol_var = tk.StringVar(value="SHA")
        ttk.Combobox(body, textvariable=self.auth_protocol_var, values=["MD5", "SHA"]).grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
        r += 1
        ttk.Label(body, text="Auth Password:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.auth_password_var = tk.StringVar(value=AUTH_PASSWORD if AUTH_PASSWORD else "authpass")
        ttk.Entry(body, textvariable=self.auth_password_var, show="*").grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
        r += 1
        ttk.Label(body, text="Privacy Protocol:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.privacy_protocol_var = tk.StringVar(value="AES")
        ttk.Combobox(body, textvariable=self.privacy_protocol_var, values=["DES", "AES"]).grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
        r += 1
        ttk.Label(body, text="Privacy Password:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.privacy_password_var = tk.StringVar(value=PRIV_PASSWORD if PRIV_PASSWORD else "privpass")
        ttk.Entry(body, textvariable=self.privacy_password_var, show="*").grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)

        # Buttons
        r += 1
        button_frame = ttk.Frame(body)
        button_frame.grid(row=r, column=0, columnspan=4, sticky='ew', padx=6, pady=6)
        ttk.Button(button_frame, text="Test Connection", command=self.test_connection).pack(side='left', padx=6)
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

            session = self.get_session()
            current_row = 0
            for i in range(1, 7):
                get_oid = f"1.3.6.1.4.1.1206.4.2.18.4.2.1.2.{i}"
                try:
                    ifm_info = session.get(get_oid)
                    formatted_value = self.format_snmp_value(ifm_info)
                    text = f"IFM Index {i}: {formatted_value}"
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

            session = self.get_session()
            current_row = 0
            for i in range(1, 7):
                for j in range(2, 5):
                    get_oid = f"1.3.6.1.4.1.1206.4.2.18.5.2.1.{j}.{i}"
                    try:
                        rfm_info = session.get(get_oid)
                        formatted_value = self.format_snmp_value(rfm_info)
                        text = f"RFM Index {j}.{i}: {formatted_value}"
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

            session = self.get_session()
            current_row = 0
            for i in range(1, 7):
                for j in range(2, 8, 5): # get entries 2 and 7 (psid and payload)
                    get_oid = f"1.3.6.1.4.1.1206.4.2.18.3.2.1.{j}.{i}"
                    try:
                        srm_info = session.get(get_oid)
                        formatted_value = self.format_snmp_value(srm_info)
                        text = f"SRM Index {j}.{i}: {formatted_value}"
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
    def get_session(self):
        """Create and return a new SNMP session with current credentials."""
        return easysnmp.Session(
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

    def test_connection(self):
        """Test SNMP connection by performing a simple GET operation."""
        try:
            session = self.get_session()

            # Try a simple GET to verify connection and permissions
            self.results_text.configure(state='normal')
            self.results_text.insert(tk.END, "Testing connection with sysDescr...\n")
            self.results_text.configure(state='disabled')
            self.update_idletasks()

            try:
                test_result = session.get('1.3.6.1.2.1.1.1.0')  # sysDescr - standard OID
                self.results_text.configure(state='normal')
                self.results_text.insert(tk.END, f"Connection OK: {test_result.value}\n\n") # type: ignore
                self.results_text.configure(state='disabled')
                self.update_idletasks()
            except easysnmp.EasySNMPError as e:
                self.results_text.configure(state='normal')
                self.results_text.insert(tk.END, f"Connection test failed: {e}\n")
                self.results_text.insert(tk.END, "Check your credentials and device accessibility.\n")
                self.results_text.configure(state='disabled')
                messagebox.showerror("Connection Error", f"Failed to connect to device:\n{e}")
                return

        except easysnmp.EasySNMPError as e:
            messagebox.showerror("SNMP Error", str(e))
            self.results_text.configure(state='normal')
            self.results_text.insert(tk.END, f"\nUnexpected error: {e}\n")
            self.results_text.configure(state='disabled')

    def destroy_entry(self, delete_oid: str, entry_widget: ttk.Entry, button_widget: ttk.Button) -> None:
        """Destroy entry for the given oid and update given UI row."""
        try:
            session = self.get_session()
            session.set(delete_oid, 6)  # 6 = destroy
            # Remove the row from UI
            entry_widget.destroy()
            button_widget.destroy()
        except easysnmp.EasySNMPError as e:
            messagebox.showerror("SNMP Error", str(e))

    def format_snmp_value(self, snmp_var):
        """Format SNMP value, converting binary data to hex string if needed."""
        value = snmp_var.value
        
        # If bytes or non-printable characters, display as hex
        if isinstance(value, bytes):
            return ' '.join(f'{b:02x}' for b in value)
        elif isinstance(value, str):
            # Check if string contains non-printable characters
            if any(ord(c) < 32 or ord(c) > 126 for c in value):
                # Convert to hex
                return ' '.join(f'{ord(c):02x}' for c in value)
        return str(value)

def main():
    root = RSUConfigurationApp()
    root.mainloop()

if __name__ == "__main__":
    main()
