#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox, ttk
from snmp import Engine, Timeout, ErrorResponse
from snmp.security.usm.auth import HmacMd5, HmacSha, HmacSha256, HmacSha512
from snmp.security.usm.priv import DesCbc, AesCfb128
from snmp.smi import OctetString, Integer32
import os
from dotenv import load_dotenv
from binascii import unhexlify
import cr_helper

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

# Initialize SNMP Engine
snmp_engine = Engine()

# Load SNMP credentials from environment variables
IP_ADDRESS = os.getenv('IP_ADDRESS')
SNMP_PORT = int(os.getenv('SNMP_PORT', 161))
SNMP_USER = os.getenv('SNMP_USER')
AUTH_PASSWORD = os.getenv('AUTH_PASSWORD')
PRIV_PASSWORD = os.getenv('PRIV_PASSWORD')

class RSUConfigurationApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RSU Configuration")
        self.geometry("900x700")
        self.resizable(True, True)

        # Create notebook for tabs
        notebook = ttk.Notebook(self)
        notebook.pack(fill='both', expand=True, padx=12, pady=12)

        # Create tabs
        self.create_credentials_tab(notebook)
        self.create_immediate_forward_tab(notebook)
        self.create_received_message_forward_tab(notebook)
        self.create_store_and_repeat_tab(notebook)

    def create_credentials_tab(self, notebook):
        """Create the SNMP Credentials tab"""
        body = ttk.Frame(notebook, padding=12)
        notebook.add(body, text="SNMP Credentials")

        # Make grid resizable
        body.columnconfigure(1, weight=1)
        body.columnconfigure(2, weight=1)

        # SNMP session input fields
        r = 0
        ttk.Label(body, text="RSU IP Address:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.hostname_var = tk.StringVar(value=IP_ADDRESS if IP_ADDRESS else "192.168.55.20")
        ttk.Entry(body, textvariable=self.hostname_var).grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
        r += 1
        ttk.Label(body, text="RSU SNMP Port:").grid(row=r, column=0, sticky='e', padx=6, pady=6)
        self.port_var = tk.IntVar(value=SNMP_PORT if SNMP_PORT else 161)
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
        ttk.Combobox(body, textvariable=self.auth_protocol_var, values=["MD5", "SHA", "SHA256", "SHA512"]).grid(row=r, column=1, columnspan=2, sticky='ew', padx=6, pady=6)
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
        ttk.Button(button_frame, text="Help", command=lambda: self.show_help("SNMP Credentials", "")).pack(side='left', padx=6)
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
        ifm_tab.rowconfigure(2, weight=1)

        # Controls row
        controls = ttk.Frame(ifm_tab)
        controls.grid(row=0, column=0, sticky='ew', padx=6, pady=6)

        # Configuration section
        config_frame = ttk.LabelFrame(ifm_tab, text="Configure IFM Entries", padding=8)
        config_frame.grid(row=1, column=0, sticky='ew', padx=6, pady=6)
        config_frame.columnconfigure(0, weight=1)

        # Container for IFM rows (display results)
        rows_frame = ttk.Frame(ifm_tab)
        rows_frame.grid(row=2, column=0, sticky='nsew', padx=6, pady=6)
        rows_frame.columnconfigure(0, weight=1)

        # Storage for IFM entry configurations
        ifm_entries = []

        def set_single_ifm_entry(entry_vars: dict, ifm_index: int) -> None:
            """Configure a single IFM entry."""
            try:
                # Get values from the form
                psid = entry_vars['psid'].get().strip()
                channel = entry_vars['channel'].get()
                enable = entry_vars['enable'].get()
                priority = entry_vars['priority'].get()
                options = entry_vars['options'].get().strip()
                payload = entry_vars['payload'].get().strip()

                # Validate inputs
                if not psid:
                    messagebox.showerror("Validation Error", f"Entry {ifm_index}: PSID cannot be empty")
                    return

                # RSU must be in standby mode to accept configuration changes
                self._set_standby() 

                # Configure the entry using SET operations
                print(f"Configuring IFM entry {ifm_index}")
                session = self.get_session()
                base_oid = f"1.3.6.1.4.1.1206.4.2.18.4.2.1"
                session.set(
                    (f"{base_oid}.2.{ifm_index}", OctetString(unhexlify(psid))),      # rsuIFMPsid (octet string as hex)
                    (f"{base_oid}.3.{ifm_index}", Integer32(int(channel))),           # rsuIFMTxChannel (integer)
                    (f"{base_oid}.4.{ifm_index}", Integer32(int(enable))),            # rsuIFMEnable
                    (f"{base_oid}.5.{ifm_index}", Integer32(4)),                      # rsuIFMStatus (4=createAndGo)
                    (f"{base_oid}.6.{ifm_index}", Integer32(int(priority))),          # rsuIFMPriority
                    (f"{base_oid}.7.{ifm_index}", OctetString(unhexlify(options))),   # rsuIFMOptions (bits)
                    (f"{base_oid}.8.{ifm_index}", OctetString(unhexlify(payload)))    # rsuIFMPayload (hex)
                )

                # Return RSU to operate mode
                self._set_operate()

                messagebox.showinfo("Success", f"Successfully configured IFM entry {ifm_index} with PSID {psid}")
                # Refresh the display
                get_ifm_info()

            except Exception as e:
                messagebox.showerror("SNMP Error", f"Failed to set IFM entry {ifm_index}: {e}")

        def add_ifm_entry() -> None:
            """Add a new configurable IFM entry form with configurable index."""
            # Configurable index input (defaults to next available index or 1)
            default_index = (ifm_entries[-1]['index'] + 1) if ifm_entries else 1
            index_var = tk.IntVar(value=default_index)

            # Create a frame for this entry
            entry_frame = ttk.LabelFrame(config_frame, text=f"IFM Entry {index_var.get()}", padding=8)
            row_pos = len(ifm_entries)
            entry_frame.grid(row=row_pos, column=0, sticky='ew', padx=4, pady=4)
            entry_frame.columnconfigure(1, weight=1)
            entry_frame.columnconfigure(3, weight=1)

            # Create variables for this entry
            idx_val = index_var.get()
            entry_vars = {
                'index_var': index_var,
                'psid': tk.StringVar(value='8002' if idx_val == 1 else 
                                          '8003' if idx_val == 2 else 
                                          '8010' if idx_val == 3 else 
                                          '0027' if idx_val == 4 else 'E0000017'),
                'channel': tk.IntVar(value=183),
                'enable': tk.IntVar(value=1),
                'priority': tk.IntVar(value=5),
                'options': tk.StringVar(value='00'),
                'payload': tk.StringVar(value='FE'),
                'frame': entry_frame,
                'index': idx_val
            }

            # Row 0: Index and PSID
            ttk.Label(entry_frame, text="IFM Index:").grid(row=0, column=0, sticky='e', padx=4, pady=2)
            def on_index_change(*_args):
                # Gracefully handle empty/non-integer input while typing
                try:
                    new_idx = int(index_var.get())
                except Exception:
                    # Keep previous index, do not crash while the field is temporarily empty
                    new_idx = entry_vars.get('index', default_index)
                # Clamp to valid range (1..32 typical, but allow >=1)
                if new_idx < 1:
                    new_idx = 1
                    index_var.set(new_idx)
                entry_vars['index'] = new_idx
                entry_frame.configure(text=f"IFM Entry {entry_vars['index']}")
            index_var.trace_add('write', on_index_change)
            ttk.Entry(entry_frame, textvariable=index_var, width=8).grid(row=0, column=1, sticky='w', padx=4, pady=2)

            ttk.Label(entry_frame, text="PSID (hex):").grid(row=0, column=2, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['psid'], width=15).grid(row=0, column=3, sticky='ew', padx=4, pady=2)

            # Row 1: Channel and Priority
            ttk.Label(entry_frame, text="Channel:").grid(row=1, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['channel'], width=10, state="readonly").grid(row=1, column=1, sticky='w', padx=4, pady=2)
            ttk.Label(entry_frame, text="Priority:").grid(row=1, column=2, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['priority'], width=10).grid(row=1, column=3, sticky='ew', padx=4, pady=2)

            # Row 2: Enable and Options
            ttk.Label(entry_frame, text="Enable (0/1):").grid(row=2, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['enable'], width=10, state="readonly").grid(row=2, column=1, sticky='w', padx=4, pady=2)
            ttk.Label(entry_frame, text="Options (hex):").grid(row=2, column=2, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['options'], width=15).grid(row=2, column=3, sticky='ew', padx=4, pady=2)

            # Row 3: Payload
            ttk.Label(entry_frame, text="Payload (hex):").grid(row=3, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['payload'], width=20).grid(row=3, column=1, columnspan=3, sticky='ew', padx=4, pady=2)

            # Row 4: Button frame for Set and Remove buttons
            button_frame = ttk.Frame(entry_frame)
            button_frame.grid(row=4, column=0, columnspan=4, pady=4)
            set_btn = ttk.Button(button_frame, text="Set Entry", command=lambda: set_single_ifm_entry(entry_vars, entry_vars['index']))
            set_btn.pack(side='left', padx=4)
            remove_btn = ttk.Button(button_frame, text="Remove Entry", command=lambda: remove_ifm_entry(entry_vars))
            remove_btn.pack(side='left', padx=4)

            ifm_entries.append(entry_vars)

        def remove_ifm_entry(entry_vars: dict) -> None:
            """Remove an IFM entry form."""
            entry_vars['frame'].destroy()
            ifm_entries.remove(entry_vars)
            # Update titles to reflect each entry's configured index
            for entry in ifm_entries:
                entry['frame'].configure(text=f"IFM Entry {entry['index']}")

        def destroy_ifm_entry(idx: int, entry_widget: ttk.Entry, button_widget: ttk.Button) -> None:
            """Destroy IFM entry for the given index and update given UI row."""
            delete_ifm_oid = f"1.3.6.1.4.1.1206.4.2.18.4.2.1.5.{idx}"
            # RSU must be in standby mode to accept configuration changes
            self._set_standby()
            self.destroy_entry(delete_ifm_oid, entry_widget, button_widget)
            # Return RSU to operate mode
            self._set_operate()

        def get_ifm_info() -> None:
            """Fetch IFM info and render each result as a read-only row with a Destroy button."""
            # Clear previous rows
            for child in rows_frame.winfo_children():
                child.destroy()
            # Enable the "Add IFM Entry" button after first Get
            add_ifm_btn.configure(state='normal')


            session = self.get_session()
            current_row = 0
            for i in range(1, 7):
                get_oid = f"1.3.6.1.4.1.1206.4.2.18.4.2.1.2.{i}"
                try:
                    handle = session.get(get_oid)
                    varbind_list = handle.wait() if hasattr(handle, 'wait') else handle  # type: ignore
                    formatted_value = self.format_snmp_value(varbind_list[0])  # type: ignore
                    text = f"IFM Index {i}: {formatted_value}"
                    var = tk.StringVar(value=text)
                    entry = ttk.Entry(rows_frame, textvariable=var, state='readonly')
                    entry._var = var  # type: ignore  # Keep StringVar alive
                    entry.grid(row=current_row, column=0, sticky='ew', padx=4, pady=2)
                    btn = ttk.Button(rows_frame, text="Destroy")
                    btn.grid(row=current_row, column=1, sticky='w', padx=4, pady=2)
                    btn.configure(command=lambda idx=i, e=entry, b=btn: destroy_ifm_entry(idx, e, b))
                    current_row += 1
                except (Timeout, ErrorResponse) as e:
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
                    messagebox.showerror("SNMP Error", str(e))

        # Create buttons with "Add IFM Entry" initially disabled
        add_ifm_btn = ttk.Button(controls, text="Add IFM Entry", command=add_ifm_entry, state='disabled')
        add_ifm_btn.pack(side='left', padx=6)
        ttk.Button(controls, text="Get IFM Info", command=get_ifm_info).pack(side='left', padx=6)
        ttk.Button(controls, text="Help", command=lambda: self.show_help("Immediate Forward", self.get_ifm_help_content())).pack(side='left', padx=6)

    def create_received_message_forward_tab(self, notebook):
        """Create the Received Message Forward tab"""
        rmf_tab = ttk.Frame(notebook, padding=12)
        notebook.add(rmf_tab, text="Received Message Forward")

        # Layout config
        rmf_tab.columnconfigure(0, weight=1)
        rmf_tab.rowconfigure(2, weight=1)

        # Controls row
        controls = ttk.Frame(rmf_tab)
        controls.grid(row=0, column=0, sticky='ew', padx=6, pady=6)

        # Configuration section
        config_frame = ttk.LabelFrame(rmf_tab, text="Configure RFM Entries", padding=8)
        config_frame.grid(row=1, column=0, sticky='ew', padx=6, pady=6)
        config_frame.columnconfigure(0, weight=1)

        # Container for RFM rows (display results)
        rows_frame = ttk.Frame(rmf_tab)
        rows_frame.grid(row=2, column=0, sticky='nsew', padx=6, pady=6)
        rows_frame.columnconfigure(0, weight=1)

        # Storage for RFM entry configurations
        rfm_entries = []

        def set_single_rfm_entry(entry_vars: dict, rfm_index: int) -> None:
            """Configure a single RFM entry."""
            try:
                # Get values from the form
                psid = entry_vars['psid'].get().strip()
                dest_ip = entry_vars['dest_ip'].get().strip()
                dest_port = entry_vars['dest_port'].get()
                protocol = entry_vars['protocol'].get()
                rssi = entry_vars['rssi'].get()
                interval = entry_vars['interval'].get()
                start_date = entry_vars['start_date'].get().strip()
                stop_date = entry_vars['stop_date'].get().strip()
                secure = entry_vars['secure'].get()
                auth_interval = entry_vars['auth_interval'].get()

                # Validate inputs
                if not psid:
                    messagebox.showerror("Validation Error", f"Entry {rfm_index}: PSID cannot be empty")
                    return
                if not dest_ip:
                    messagebox.showerror("Validation Error", f"Entry {rfm_index}: Destination IP cannot be empty")
                    return

                # Convert date strings to SNMP DateAndTime format
                try:
                    start_date_bytes = cr_helper.convert_datetime_to_snmp(start_date)
                    stop_date_bytes = cr_helper.convert_datetime_to_snmp(stop_date)
                except ValueError as e:
                    messagebox.showerror("Validation Error", f"Entry {rfm_index}: {e}")
                    return

                # RSU must be in standby mode to accept configuration changes
                self._set_standby()

                # Configure the entry using SET operations
                print(f"Configuring RFM entry {rfm_index}")
                session = self.get_session()
                base_oid = f"1.3.6.1.4.1.1206.4.2.18.5.2.1"
                session.set(
                    (f"{base_oid}.2.{rfm_index}", OctetString(unhexlify(psid))),        # rsuReceivedMsgPsid (hex)
                    (f"{base_oid}.3.{rfm_index}", OctetString(dest_ip.encode())),       # rsuReceivedMsgDestIpAddr (string)
                    (f"{base_oid}.4.{rfm_index}", Integer32(int(dest_port))),           # rsuReceivedMsgDestPort (integer)
                    (f"{base_oid}.5.{rfm_index}", Integer32(int(protocol))),            # rsuReceivedMsgProtocol (integer)
                    (f"{base_oid}.6.{rfm_index}", Integer32(int(rssi))),                # rsuReceivedMsgRssi (integer)
                    (f"{base_oid}.7.{rfm_index}", Integer32(int(interval))),            # rsuReceivedMsgInterval (integer)
                    (f"{base_oid}.8.{rfm_index}", OctetString(start_date_bytes)),       # rsuReceivedMsgDeliveryStart (DateAndTime)
                    (f"{base_oid}.9.{rfm_index}", OctetString(stop_date_bytes)),        # rsuReceivedMsgDeliveryStop (DateAndTime)
                    (f"{base_oid}.10.{rfm_index}", Integer32(4)),                       # rsuReceivedMsgStatus (4=createAndGo)
                    (f"{base_oid}.11.{rfm_index}", Integer32(int(secure))),             # rsuReceivedMsgSecure (integer)
                    (f"{base_oid}.12.{rfm_index}", Integer32(int(auth_interval)))       # rsuReceivedMsgAuthMsgInterval (integer)
                )

                # Return RSU to operate mode
                self._set_operate()

                messagebox.showinfo("Success", f"Successfully configured RFM entry {rfm_index} with PSID {psid}")
                # Refresh the display
                get_rfm_info()

            except Exception as e:
                messagebox.showerror("SNMP Error", f"Failed to set RFM entry {rfm_index}: {e}")

        def add_rfm_entry() -> None:
            """Add a new configurable RFM entry form with configurable index."""
            # Configurable index input (defaults to next available index or 1)
            default_index = (rfm_entries[-1]['index'] + 1) if rfm_entries else 1
            index_var = tk.IntVar(value=default_index)

            # Create a frame for this entry
            entry_frame = ttk.LabelFrame(config_frame, text=f"RFM Entry {index_var.get()}", padding=8)
            row_pos = len(rfm_entries)
            entry_frame.grid(row=row_pos, column=0, sticky='ew', padx=4, pady=4)
            entry_frame.columnconfigure(1, weight=1)
            entry_frame.columnconfigure(3, weight=1)

            # Create variables for this entry
            idx_val = index_var.get()
            entry_vars = {
                'index_var': index_var,
                'psid': tk.StringVar(value='8002' if idx_val == 1 else '8003'),
                'dest_ip': tk.StringVar(value='192.168.55.152'),
                'dest_port': tk.IntVar(value=5398),
                'protocol': tk.IntVar(value=2),  # 2=UDP
                'rssi': tk.IntVar(value=-100),
                'interval': tk.IntVar(value=1),
                'start_date': tk.StringVar(value='2025-01-01,00:00:00.0'),
                'stop_date': tk.StringVar(value='2030-01-01,00:00:00.0'),
                'secure': tk.IntVar(value=0),
                'auth_interval': tk.IntVar(value=0),
                'frame': entry_frame,
                'index': idx_val
            }

            # Row 0: Index and PSID
            ttk.Label(entry_frame, text="RFM Index:").grid(row=0, column=0, sticky='e', padx=4, pady=2)
            def on_index_change(*_args):
                # Gracefully handle empty/non-integer input while typing
                try:
                    new_idx = int(index_var.get())
                except Exception:
                    # Keep previous index, do not crash while the field is temporarily empty
                    new_idx = entry_vars.get('index', default_index)
                # Clamp to valid range (1..32 typical, but allow >=1)
                if new_idx < 1:
                    new_idx = 1
                    index_var.set(new_idx)
                entry_vars['index'] = new_idx
                entry_frame.configure(text=f"RFM Entry {entry_vars['index']}")
            index_var.trace_add('write', on_index_change)
            ttk.Entry(entry_frame, textvariable=index_var, width=8).grid(row=0, column=1, sticky='w', padx=4, pady=2)

            ttk.Label(entry_frame, text="PSID (hex):").grid(row=0, column=2, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['psid'], width=15).grid(row=0, column=3, sticky='ew', padx=4, pady=2)

            # Row 1: Destination IP and Port
            ttk.Label(entry_frame, text="Dest IP:").grid(row=1, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['dest_ip'], width=15).grid(row=1, column=1, sticky='ew', padx=4, pady=2)
            ttk.Label(entry_frame, text="Dest Port:").grid(row=1, column=2, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['dest_port'], width=10).grid(row=1, column=3, sticky='ew', padx=4, pady=2)

            # Row 2: Protocol and RSSI
            ttk.Label(entry_frame, text="Protocol:").grid(row=2, column=0, sticky='e', padx=4, pady=2)
            ttk.Combobox(entry_frame, textvariable=entry_vars['protocol'], values=['2'], width=8, state="readonly").grid(row=2, column=1, sticky='w', padx=4, pady=2)
            ttk.Label(entry_frame, text="RSSI:").grid(row=2, column=2, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['rssi'], width=10, state="readonly").grid(row=2, column=3, sticky='ew', padx=4, pady=2)

            # Row 3: Interval and Secure
            ttk.Label(entry_frame, text="Interval:").grid(row=3, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['interval'], width=10).grid(row=3, column=1, sticky='w', padx=4, pady=2)
            ttk.Label(entry_frame, text="Secure (0/1):").grid(row=3, column=2, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['secure'], width=10).grid(row=3, column=3, sticky='ew', padx=4, pady=2)

            # Row 4: Start Date
            ttk.Label(entry_frame, text="Start Date:").grid(row=4, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['start_date'], width=20).grid(row=4, column=1, columnspan=3, sticky='ew', padx=4, pady=2)

            # Row 5: Stop Date
            ttk.Label(entry_frame, text="Stop Date:").grid(row=5, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['stop_date'], width=20).grid(row=5, column=1, columnspan=3, sticky='ew', padx=4, pady=2)

            # Row 6: Auth Interval
            ttk.Label(entry_frame, text="Auth Msg Interval:").grid(row=6, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['auth_interval'], width=10).grid(row=6, column=1, sticky='w', padx=4, pady=2)

            # Row 7: Button frame for Set and Remove buttons
            button_frame = ttk.Frame(entry_frame)
            button_frame.grid(row=7, column=0, columnspan=4, pady=4)
            set_btn = ttk.Button(button_frame, text="Set Entry", command=lambda: set_single_rfm_entry(entry_vars, entry_vars['index']))
            set_btn.pack(side='left', padx=4)
            remove_btn = ttk.Button(button_frame, text="Remove Entry", command=lambda: remove_rfm_entry(entry_vars))
            remove_btn.pack(side='left', padx=4)

            rfm_entries.append(entry_vars)

        def remove_rfm_entry(entry_vars: dict) -> None:
            """Remove an RFM entry form."""
            entry_vars['frame'].destroy()
            rfm_entries.remove(entry_vars)
            # Update titles to reflect each entry's configured index
            for entry in rfm_entries:
                entry['frame'].configure(text=f"RFM Entry {entry['index']}")

        def destroy_rfm_entry(idx: int, entry_widget: ttk.Entry, button_widget: ttk.Button) -> None:
            """Destroy RFM entry for the given index and update given UI row."""
            delete_rfm_oid = f"1.3.6.1.4.1.1206.4.2.18.5.2.1.10.{idx}"
            self.destroy_entry(delete_rfm_oid, entry_widget, button_widget)

        def get_rfm_info() -> None:
            """Fetch RFM info and render each result as a read-only row with a Destroy button."""
            # Clear previous rows
            for child in rows_frame.winfo_children():
                child.destroy()
            # Enable the "Add RFM Entry" button after first Get
            add_rfm_btn.configure(state='normal')

            session = self.get_session()
            current_row = 0
            for i in range(1, 7):
                for j in range(2, 5):
                    get_oid = f"1.3.6.1.4.1.1206.4.2.18.5.2.1.{j}.{i}"
                    try:
                        handle = session.get(get_oid)
                        varbind_list = handle.wait() if hasattr(handle, 'wait') else handle  # type: ignore
                        formatted_value = self.format_snmp_value(varbind_list[0])  # type: ignore
                        text = f"RFM Index {i}: {formatted_value}"
                        var = tk.StringVar(value=text)
                        entry = ttk.Entry(rows_frame, textvariable=var, state='readonly')
                        entry._var = var  # type: ignore  # Keep StringVar alive
                        entry.grid(row=current_row, column=0, sticky='ew', padx=4, pady=2)
                        btn = ttk.Button(rows_frame, text="Destroy")
                        btn.grid(row=current_row, column=1, sticky='w', padx=4, pady=2)
                        btn.configure(command=lambda idx=i, e=entry, b=btn: destroy_rfm_entry(idx, e, b))
                        current_row += 1
                    except (Timeout, ErrorResponse) as e:
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

        # Create buttons with "Add RFM Entry" initially disabled
        add_rfm_btn = ttk.Button(controls, text="Add RFM Entry", command=add_rfm_entry, state='disabled')
        add_rfm_btn.pack(side='left', padx=6)
        ttk.Button(controls, text="Get RFM Info", command=get_rfm_info).pack(side='left', padx=6)
        ttk.Button(controls, text="Help", command=lambda: self.show_help("Received Message Forward", self.get_rfm_help_content())).pack(side='left', padx=6)

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

        # Configuration section
        config_frame = ttk.LabelFrame(srm_tab, text="Configure SRM Entries", padding=8)
        config_frame.grid(row=1, column=0, sticky='ew', padx=6, pady=6)
        config_frame.columnconfigure(0, weight=1)

        # Container for SRM rows (display results)
        rows_frame = ttk.Frame(srm_tab)
        rows_frame.grid(row=2, column=0, sticky='nsew', padx=6, pady=6)
        rows_frame.columnconfigure(0, weight=1)

        # Storage for SRM entry configurations
        srm_entries = []

        def destroy_srm_entry(idx: int, entry_widget: ttk.Entry, button_widget: ttk.Button) -> None:
            """Destroy SRM entry for the given index and update given UI row."""
            delete_srm_oid = f"1.3.6.1.4.1.1206.4.2.18.3.2.1.9.{idx}"
            self.destroy_entry(delete_srm_oid, entry_widget, button_widget)

        def get_srm_info() -> None:
            """Fetch SRM info and render each result as a read-only row with a Destroy button."""
            # Clear previous rows
            for child in rows_frame.winfo_children():
                child.destroy()
            # Enable the "Add SRM Entry" button after first Get
            add_srm_btn.configure(state='normal')

            session = self.get_session()
            current_row = 0
            for i in range(1, 7):
                for j in range(2, 8, 5): # get entries 2 and 7 (psid and payload)
                    get_oid = f"1.3.6.1.4.1.1206.4.2.18.3.2.1.{j}.{i}"
                    try:
                        handle = session.get(get_oid)
                        varbind_list = handle.wait() if hasattr(handle, 'wait') else handle  # type: ignore
                        formatted_value = self.format_snmp_value(varbind_list[0])  # type: ignore
                        text = f"SRM Index {i}: {formatted_value}"
                        var = tk.StringVar(value=text)
                        entry = ttk.Entry(rows_frame, textvariable=var, state='readonly')
                        entry._var = var  # type: ignore  # Keep StringVar alive
                        entry.grid(row=current_row, column=0, sticky='ew', padx=4, pady=2)
                        btn = ttk.Button(rows_frame, text="Destroy")
                        btn.grid(row=current_row, column=1, sticky='w', padx=4, pady=2)
                        btn.configure(command=lambda idx=i, e=entry, b=btn: destroy_srm_entry(idx, e, b))
                        current_row += 1
                    except (Timeout, ErrorResponse) as e:
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

        def set_single_srm_entry(entry_vars: dict, srm_index: int) -> None:
            """Configure a single SRM entry."""
            try:
                # Get values from the form
                psid = entry_vars['psid'].get().strip()
                channel = entry_vars['channel'].get()
                interval = entry_vars['interval'].get()
                start_date = entry_vars['start_date'].get().strip()
                stop_date = entry_vars['stop_date'].get().strip()
                payload = entry_vars['payload'].get().strip()
                enable = entry_vars['enable'].get()
                priority = entry_vars['priority'].get()
                options = entry_vars['options'].get().strip()

                # Validate inputs
                if not psid:
                    messagebox.showerror("Validation Error", f"Entry {srm_index}: PSID cannot be empty")
                    return
                if not payload:
                    messagebox.showerror("Validation Error", f"Entry {srm_index}: Payload cannot be empty")
                    return

                # Convert date strings to SNMP DateAndTime format
                try:
                    start_date_bytes = cr_helper.convert_datetime_to_snmp(start_date)
                    stop_date_bytes = cr_helper.convert_datetime_to_snmp(stop_date)
                except ValueError as e:
                    messagebox.showerror("Validation Error", f"Entry {srm_index}: {e}")
                    return

                # RSU must be in standby mode to accept configuration changes
                self._set_standby()

                # Configure the entry using SET operations
                print(f"Configuring SRM entry {srm_index}")
                session = self.get_session()
                base_oid = f"1.3.6.1.4.1.1206.4.2.18.3.2.1"
                session.set(
                    (f"{base_oid}.2.{srm_index}", OctetString(unhexlify(psid))),        # rsuMsgRepeatPsid (hex)
                    (f"{base_oid}.3.{srm_index}", Integer32(int(channel))),             # rsuMsgRepeatTxChannel (integer)
                    (f"{base_oid}.4.{srm_index}", Integer32(int(interval))),            # rsuMsgRepeatTxInterval (integer)
                    (f"{base_oid}.5.{srm_index}", OctetString(start_date_bytes)),       # rsuMsgRepeatDeliveryStart (DateAndTime)
                    (f"{base_oid}.6.{srm_index}", OctetString(stop_date_bytes)),        # rsuMsgRepeatDeliveryStop (DateAndTime)
                    (f"{base_oid}.7.{srm_index}", OctetString(unhexlify(payload))),     # rsuMsgRepeatPayload (hex)
                    (f"{base_oid}.8.{srm_index}", Integer32(int(enable))),              # rsuMsgRepeatEnable (integer)
                    (f"{base_oid}.9.{srm_index}", Integer32(4)),                        # rsuMsgRepeatStatus (4=createAndGo)
                    (f"{base_oid}.10.{srm_index}", Integer32(int(priority))),           # rsuMsgRepeatPriority (integer)
                    (f"{base_oid}.11.{srm_index}", OctetString(unhexlify(options)))     # rsuMsgRepeatOptions (BITS)
                )

                # Return RSU to operate mode
                self._set_operate()

                messagebox.showinfo("Success", f"Successfully configured SRM entry {srm_index} with PSID {psid}")
                # Refresh the display
                get_srm_info()

            except Exception as e:
                messagebox.showerror("SNMP Error", f"Failed to set SRM entry {srm_index}: {e}")

        def add_srm_entry() -> None:
            """Add a new configurable SRM entry form with configurable index."""
            # Configurable index input (defaults to next available index or 1)
            default_index = (srm_entries[-1]['index'] + 1) if srm_entries else 1
            index_var = tk.IntVar(value=default_index)

            # Create a frame for this entry
            entry_frame = ttk.LabelFrame(config_frame, text=f"SRM Entry {index_var.get()}", padding=8)
            row_pos = len(srm_entries)
            entry_frame.grid(row=row_pos, column=0, sticky='ew', padx=4, pady=4)
            entry_frame.columnconfigure(1, weight=1)
            entry_frame.columnconfigure(3, weight=1)

            # Create variables for this entry
            idx_val = index_var.get()
            entry_vars = {
                'index_var': index_var,
                'psid': tk.StringVar(value='8002'),
                'channel': tk.IntVar(value=183),
                'interval': tk.IntVar(value=1000),
                'start_date': tk.StringVar(value='2025-01-01,00:00:00.0'),
                'stop_date': tk.StringVar(value='2030-01-01,00:00:00.0'),
                'payload': tk.StringVar(value='FF'),
                'enable': tk.IntVar(value=1),
                'priority': tk.IntVar(value=6),
                'options': tk.StringVar(value='01'),
                'frame': entry_frame,
                'index': idx_val
            }

            # Row 0: Index and PSID
            ttk.Label(entry_frame, text="SRM Index:").grid(row=0, column=0, sticky='e', padx=4, pady=2)
            def on_index_change(*_args):
                # Gracefully handle empty/non-integer input while typing
                try:
                    new_idx = int(index_var.get())
                except Exception:
                    # Keep previous index, do not crash while the field is temporarily empty
                    new_idx = entry_vars.get('index', default_index)
                # Clamp to valid range (1..32 typical, but allow >=1)
                if new_idx < 1:
                    new_idx = 1
                    index_var.set(new_idx)
                entry_vars['index'] = new_idx
                entry_frame.configure(text=f"SRM Entry {entry_vars['index']}")
            index_var.trace_add('write', on_index_change)
            ttk.Entry(entry_frame, textvariable=index_var, width=8).grid(row=0, column=1, sticky='w', padx=4, pady=2)

            ttk.Label(entry_frame, text="PSID (hex):").grid(row=0, column=2, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['psid'], width=15).grid(row=0, column=3, sticky='ew', padx=4, pady=2)

            # Row 1: Channel and Interval
            ttk.Label(entry_frame, text="TX Channel:").grid(row=1, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['channel'], width=10, state="readonly").grid(row=1, column=1, sticky='w', padx=4, pady=2)
            ttk.Label(entry_frame, text="TX Interval (ms):").grid(row=1, column=2, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['interval'], width=10).grid(row=1, column=3, sticky='ew', padx=4, pady=2)

            # Row 2: Start Date
            ttk.Label(entry_frame, text="Start Date:").grid(row=2, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['start_date'], width=20).grid(row=2, column=1, columnspan=3, sticky='ew', padx=4, pady=2)

            # Row 3: Stop Date
            ttk.Label(entry_frame, text="Stop Date:").grid(row=3, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['stop_date'], width=20).grid(row=3, column=1, columnspan=3, sticky='ew', padx=4, pady=2)

            # Row 4: Payload
            ttk.Label(entry_frame, text="Payload (hex):").grid(row=4, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['payload'], width=20).grid(row=4, column=1, columnspan=3, sticky='ew', padx=4, pady=2)

            # Row 5: Enable and Priority
            ttk.Label(entry_frame, text="Enable (0/1):").grid(row=5, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['enable'], width=10).grid(row=5, column=1, sticky='w', padx=4, pady=2)
            ttk.Label(entry_frame, text="Priority:").grid(row=5, column=2, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['priority'], width=10).grid(row=5, column=3, sticky='ew', padx=4, pady=2)

            # Row 6: Options
            ttk.Label(entry_frame, text="Options (hex):").grid(row=6, column=0, sticky='e', padx=4, pady=2)
            ttk.Entry(entry_frame, textvariable=entry_vars['options'], width=15).grid(row=6, column=1, columnspan=3, sticky='ew', padx=4, pady=2)

            # Row 7: Button frame for Set and Remove buttons
            button_frame = ttk.Frame(entry_frame)
            button_frame.grid(row=7, column=0, columnspan=4, pady=4)
            set_btn = ttk.Button(button_frame, text="Set Entry", command=lambda: set_single_srm_entry(entry_vars, entry_vars['index']))
            set_btn.pack(side='left', padx=4)
            remove_btn = ttk.Button(button_frame, text="Remove Entry", command=lambda: remove_srm_entry(entry_vars))
            remove_btn.pack(side='left', padx=4)

            srm_entries.append(entry_vars)

        def remove_srm_entry(entry_vars: dict) -> None:
            """Remove an SRM entry form."""
            entry_vars['frame'].destroy()
            srm_entries.remove(entry_vars)
            # Update titles to reflect each entry's configured index
            for entry in srm_entries:
                entry['frame'].configure(text=f"SRM Entry {entry['index']}")

        # Create buttons with "Add SRM Entry" initially disabled
        add_srm_btn = ttk.Button(controls, text="Add SRM Entry", command=add_srm_entry, state='disabled')
        add_srm_btn.pack(side='left', padx=6)
        ttk.Button(controls, text="Get SRM Info", command=get_srm_info).pack(side='left', padx=6)
        ttk.Button(controls, text="Help", command=lambda: self.show_help("Store-and-Repeat", self.get_srm_help_content())).pack(side='left', padx=6)

    # Methods
    def _get_rsu_mode(self) -> int:
        """Get RSU mode.
        
        Returns:
            int: Current RSU mode value. 1=other, 2=standby, 3=operate
        """
        mode_oid = "1.3.6.1.4.1.1206.4.2.18.16.2.0"
        try:
            session = self.get_session()
            handle = session.get(mode_oid)
            varbind_list = handle.wait() if hasattr(handle, 'wait') else handle  # type: ignore
            value_obj = varbind_list[0].value  # type: ignore
            current_mode = value_obj.value if hasattr(value_obj, 'value') else value_obj
            return current_mode
        except Exception as e:
            print(f"ERROR getting RSU mode: {e}")
            raise
        
    def _get_rsu_mode_status(self) -> None:
        """Get RSU mode status."""
        mode_status_oid = "1.3.6.1.4.1.1206.4.2.18.16.3.0"
        try:
            session = self.get_session()
            handle = session.get(mode_status_oid)
            varbind_list = handle.wait() if hasattr(handle, 'wait') else handle  # type: ignore
            value_obj = varbind_list[0].value  # type: ignore
            mode_status = value_obj.value if hasattr(value_obj, 'value') else value_obj
            print(f"Current RSU mode status: {mode_status}")
        except Exception as e:
            print(f"ERROR getting RSU mode status: {e}")
            raise

    def _set_rsu_mode(self, target:dict[str, int]) -> None:
        """Set RSU to target mode with retry loop."""
        mode_oid = "1.3.6.1.4.1.1206.4.2.18.16.2.0"
        target_name = list(target.keys())[0]
        target_mode = list(target.values())[0]
        print(f"Setting RSU to {target_name} mode...")

        try:
            # Check current mode
            current_mode = self._get_rsu_mode()
            if current_mode == target_mode:
                print(f"RSU is already in {target_name} mode.")
                return

            # Set the mode
            session = self.get_session()
            response = session.set((mode_oid, Integer32(target_mode)))
            print(f"Set response: {response}")
            
            # If no exception was raised, the set operation succeeded
            # The response contains variable bindings confirming the set operation
            print(f"Successfully set RSU to {target_name} mode.")
            
            # Optionally verify by reading back the mode
            try:
                verified_mode = self._get_rsu_mode()
                if verified_mode != target_mode:
                    print(f"Warning: Mode verification failed. Expected {target_mode}, got {verified_mode}")
            except Exception as verify_error:
                print(f"Note: Could not verify mode change: {verify_error}")

        except (Timeout, ErrorResponse) as e:
            print(f"SNMP error setting RSU mode: {type(e).__name__}: {e}")
            raise
        except Exception as e:
            print(f"Error setting RSU mode: {type(e).__name__}: {e}")
            raise

    def _set_standby(self) -> None:
        """Set RSU to standby mode (2)."""
        self._set_rsu_mode({"standby": 2})

    def _set_operate(self) -> None:
        """Set RSU to operate mode (3)."""
        self._set_rsu_mode({"operate": 3})
    def show_help(self, tab_name: str, content: str) -> None:
        """Show a help window for the given tab."""
        help_window = tk.Toplevel(self)
        help_window.title(f"{tab_name} Help")
        help_window.geometry("600x400")

        # Create text widget with scrollbar
        text_frame = ttk.Frame(help_window, padding=12)
        text_frame.pack(fill='both', expand=True)

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side='right', fill='y')

        help_text = tk.Text(text_frame, wrap='word', yscrollcommand=scrollbar.set)
        help_text.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=help_text.yview)

        # Insert content
        if content:
            help_text.insert('1.0', content)
        else:
            help_text.insert('1.0', f"Help content for {tab_name} will be added here.")

        help_text.configure(state='disabled')

        # Close button
        button_frame = ttk.Frame(help_window, padding=12)
        button_frame.pack(fill='x')
        ttk.Button(button_frame, text="Close", command=help_window.destroy).pack(side='right')

    def get_ifm_help_content(self) -> str:
        """Return help content for Immediate Forward tab."""
        return """Immediate Forward Messages (IFM) Configuration Help

=== IFM Entry Fields ===
For more information on each field, refer to the RSU SNMP MIB documentation section 5.5 Immediate Forward Messages.
https://www.ntcip.org/file/2025/01/NTCIP-1218-v01A-2024-AsPublished.pdf

PSID: Provider Service Identifier (hex value)
      Identifies the type of message being transmitted.

Channel: Transmission channel number (typically 172-184)
         The radio channel on which the message will be broadcast.

Enable: 0 = Disabled, 1 = Enabled
        Controls whether this IFM entry is active.

Priority: Message priority (0-63, higher is more important)
          Determines transmission priority when multiple messages compete.

Payload: Hex value containing the message data to be transmitted.


Options: Bit-mapped options (BITS, hex):
    Bit 0: 0=Bypass1609.2, 1=Process1609.2
    Bit 1: 0=Secure,       1=Unsecure
    Bit 2: 0=ContXmit,     1=NoXmitShortTermXceeded
    Bit 3: 0=ContXmit,     1=NoXmitLongTermXceeded
"""

    def get_rfm_help_content(self) -> str:
        """Return help content for Received Message Forward tab."""
        return """Received Message Forward (RFM) Configuration Help

=== RFM Entry Fields ===
For more information on each field, refer to the RSU SNMP MIB documentation section 5.6 Received Messages.
https://www.ntcip.org/file/2025/01/NTCIP-1218-v01A-2024-AsPublished.pdf

PSID: Provider Service Identifier (hex value)
      Identifies the type of message to forward when received.

Destination IP: IP address where received messages will be forwarded.
                The IP address of the destination system.

Destination Port: Port number for forwarding.
                  The port on the destination system.

Protocol: Transport protocol for forwarding
          1 = Other (A SET to a value of 'other' shall return a badValue error.)
          2 = UDP (User Datagram Protocol)

RSSI: Received Signal Strength Indicator threshold (dBm)
      Minimum signal strength required to forward message.
      Typical value: -100 (dBm)

Interval: Forwarding interval in deciseconds (1/10 second)
          Controls how often messages are forwarded.
          1 = 100ms, 10 = 1 second

Start Date: Message forwarding start date/time
            Format: yyyy-mm-dd,hh:mm:ss.ms
            Example: 2025-01-01,00:00:00.0
            This is converted to SNMP DateAndTime format (8 octets)
            Example: 2025-01-01,00:00:00.0 becomes 07 E9 01 01 00 00 00 00

Stop Date: Message forwarding stop date/time
           Format: yyyy-mm-dd,hh:mm:ss.ms
           Example: 2030-01-01,00:00:00.0
           This is converted to SNMP DateAndTime format (8 octets)

Secure: Security requirement for forwarded messages
        0 = Accept both secure and unsecure messages
        1 = Accept only secure messages

Auth Msg Interval: Authentication message interval in deciseconds
                   0 = No authentication messages
"""

    def get_srm_help_content(self) -> str:
        """Return help content for Store and Repeat Messages tab."""
        return """Store and Repeat Messages (SRM) Configuration Help

=== SRM Entry Fields ===
For more information on each field, refer to the RSU SNMP MIB documentation section 5.4 Store and Repeat Messages.
https://www.ntcip.org/file/2025/01/NTCIP-1218-v01A-2024-AsPublished.pdf

PSID: Provider Service Identifier (hex value)
      Identifies the message type to store and repeat.

TX Channel: Transmission channel number (typically 172-184)
            The radio channel used when repeating the message.

TX Interval: Transmission interval in milliseconds
             How often the stored message is repeated. (rsuMsgRepeatTxInterval)

Start Date: Message forwarding start date/time
            Format: yyyy-mm-dd,hh:mm:ss.ms
            Example: 2025-01-01,00:00:00.0
            This is converted to SNMP DateAndTime format (8 octets)
            Example: 2025-01-01,00:00:00.0 becomes 07 E9 01 01 00 00 00 00

Stop Date: Message forwarding stop date/time
           Format: yyyy-mm-dd,hh:mm:ss.ms
           Example: 2030-01-01,00:00:00.0
           This is converted to SNMP DateAndTime format (8 octets)

Payload: Hex value containing the message data to be transmitted.

Enable: 0 = Disabled, 1 = Enabled
        Controls whether this SRM entry is active (rsuMsgRepeatEnable).

Priority: Message priority (0-63, higher is more important)
          Determines transmission priority when multiple messages compete.

Options: Bit-mapped options (BITS, hex):
    Bit 0: 0=Bypass1609.2, 1=Process1609.2
    Bit 1: 0=Secure,       1=Unsecure
    Bit 2: 0=ContXmit,     1=NoXmitShortTermXceeded
    Bit 3: 0=ContXmit,     1=NoXmitLongTermXceeded
"""

    def get_session(self):
        """Create and return a new SNMP manager with current credentials."""
        # Map protocol strings to snmp library constants
        auth_protocol_map = {
            "MD5": HmacMd5,
            "SHA": HmacSha,
            "SHA256": HmacSha256,
            "SHA512": HmacSha512,
        }
        priv_protocol_map = {
            "DES": DesCbc,
            "AES": AesCfb128,
        }
        
        auth_protocol = auth_protocol_map.get(self.auth_protocol_var.get(), HmacSha)
        priv_protocol = priv_protocol_map.get(self.privacy_protocol_var.get(), AesCfb128)
        
        username = self.snmpv3_user_var.get()
        auth_password = self.auth_password_var.get()
        priv_password = self.privacy_password_var.get()
        
        # Add user to engine if not already added
        try:
            snmp_engine.addUser(
                username,
                authProtocol=auth_protocol,
                authSecret=auth_password.encode() if isinstance(auth_password, str) else auth_password,
                privProtocol=priv_protocol,
                privSecret=priv_password.encode() if isinstance(priv_password, str) else priv_password,
            )
        except Exception:
            # User may already exist; ignore error
            pass
        
        # Create and return manager
        hostname = self.hostname_var.get()
        port = self.port_var.get()
        manager = snmp_engine.Manager((hostname, port), defaultUser=username)
        return manager

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
                handle = session.get('1.3.6.1.2.1.1.1.0')  # sysDescr - standard OID
                varbind_list = handle.wait() if hasattr(handle, 'wait') else handle  # type: ignore
                formatted_value = self.format_snmp_value(varbind_list[0])  # type: ignore
                self.results_text.configure(state='normal')
                self.results_text.insert(tk.END, f"Connection OK: {formatted_value}\n\n")
                self.results_text.configure(state='disabled')
                self.update_idletasks()
            except (Timeout, ErrorResponse) as e:
                self.results_text.configure(state='normal')
                self.results_text.insert(tk.END, f"Connection test failed: {e}\n")
                self.results_text.insert(tk.END, "Check your credentials and device accessibility.\n")
                self.results_text.configure(state='disabled')
                messagebox.showerror("Connection Error", f"Failed to connect to device:\n{e}")
                return

        except (Timeout, ErrorResponse) as e:
            messagebox.showerror("SNMP Error", str(e))
            self.results_text.configure(state='normal')
            self.results_text.insert(tk.END, f"\nUnexpected error: {e}\n")
            self.results_text.configure(state='disabled')

    def destroy_entry(self, delete_oid: str, entry_widget: ttk.Entry, button_widget: ttk.Button) -> None:
        """Destroy entry for the given oid and update given UI row."""
        try:
            session = self.get_session()
            session.set((delete_oid, Integer32(6))) # This OID (RowStatus) uses INTEGER32. 6 = destroy
            # Remove the row from UI
            entry_widget.destroy()
            button_widget.destroy()
        except (Timeout, ErrorResponse) as e:
            messagebox.showerror("SNMP Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to destroy entry: {e}")

    def format_snmp_value(self, varbind):
        """Format SNMP VarBind value, converting binary data to hex string if needed, and 8-byte octet strings to datetime."""
        # varbind has .value attribute which is an snmp.smi.ObjectSyntax object
        value = varbind.value
        
        # Handle INTEGER32 types
        if hasattr(value, 'value') and isinstance(value.value, int):
            return str(value.value)
        
        # Handle different value types from snmp library
        if hasattr(value, 'data'):  # OctetString type
            data = value.data
            if isinstance(data, bytes):
                # Check if this is an 8-byte DateAndTime value
                if len(data) == 8:
                    # Try to convert to datetime string
                    datetime_str = cr_helper.convert_snmp_datetime_to_string(data)
                    # Only return as datetime if it looks valid (not all hex)
                    if ',' in datetime_str and '-' in datetime_str:
                        return datetime_str
                
                # Try to decode as UTF-8 string first
                try:
                    decoded_str = data.decode('utf-8')
                    # If it's printable, return as string
                    if all(32 <= ord(c) <= 126 or c in '\t\n\r' for c in decoded_str):
                        return decoded_str
                except (UnicodeDecodeError, AttributeError):
                    pass
                
                # Return as hex string if not printable
                return ' '.join(f'{b:02x}' for b in data)
            elif isinstance(data, str):
                return data
            return str(data)
        elif isinstance(value, bytes):
            # Check if this is an 8-byte DateAndTime value
            if len(value) == 8:
                datetime_str = cr_helper.convert_snmp_datetime_to_string(value)
                if ',' in datetime_str and '-' in datetime_str:
                    return datetime_str
            
            # Try to decode as UTF-8 string first
            try:
                decoded_str = value.decode('utf-8')
                # If it's printable, return as string
                if all(32 <= ord(c) <= 126 or c in '\t\n\r' for c in decoded_str):
                    return decoded_str
            except (UnicodeDecodeError, AttributeError):
                pass
            
            return ' '.join(f'{b:02x}' for b in value)
        elif isinstance(value, str):
            # Check if string contains non-printable characters
            if any(ord(c) < 32 or ord(c) > 126 for c in value):
                # Convert to hex
                return ' '.join(f'{ord(c):02x}' for c in value)
            return value
        elif isinstance(value, int):
            return str(value)
        
        return str(value)

def main():
    root = RSUConfigurationApp()
    root.mainloop()

if __name__ == "__main__":
    main()
