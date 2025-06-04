# Written (mostly) by Gemini-2.5-Pro-Preview

import email.message
import tkinter as tk
from tkinter import ttk, messagebox
from imaplib import IMAP4_SSL, Time2Internaldate
import email
from email.header import decode_header
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import threading # Added for threading
import queue # Added for thread-safe communication

# --- Configuration ---
# TODO: Fill in your Gmail address and password below.
# For Gmail, you might need to generate an "App Password" if you have 2-Factor Authentication enabled.
MY_ADDRESS = "your_email@gmail.com"
MY_PASSWORD = "your_password"

GMAIL_IMAP_SERVER = 'imap.gmail.com'
GMAIL_IMAP_PORT = 993
SENT_MAIL_FOLDER = 'Inbox' 
# Common Gmail Sent folder. May vary based on language or settings (e.g., 'Sent', 'Sent Items').

# --- Email Processing Logic ---
def create_modified_email(client_obj: IMAP4_SSL, 
                          target_mailbox: str,
                          new_sent_date_jst: datetime, 
                          new_received_date: datetime,
                          new_from_header: str,
                          original_message_obj: email.message.Message,
                          my_email_address: str
                          ):
    msg_copy = email.message_from_bytes(original_message_obj.as_bytes())
    if 'From' in msg_copy: del msg_copy['From']
    if 'To' in msg_copy: del msg_copy['To']
    if 'Date' in msg_copy: del msg_copy['Date']
    if 'Received' in msg_copy: del msg_copy['Received']
    
    msg_copy['Date'] = new_sent_date_jst.strftime('%a, %d %b %Y %H:%M:%S %z')
    msg_copy['Received'] = new_received_date.strftime('%a, %d %b %Y %H:%M:%S %z')
    
    final_email_str = f'From: {new_from_header}\nTo: {my_email_address}\n{str(msg_copy)}'
    
    imap_internal_date_timestamp = new_received_date.timestamp() 
    internal_date_imap_format = Time2Internaldate(imap_internal_date_timestamp)
    
    client_obj.append(target_mailbox, '', internal_date_imap_format, final_email_str.encode('utf-8'))

class EmailProcessorApp:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("Email Modifier and Re-Importer")
        self.root.geometry("1000x750")

        self.client = None
        self.sender_history = []
        self.fetched_emails_cache = [] 
        self.editable_mails_data = []
        
        # Queue for results from worker thread
        self.fetch_results_queue = queue.Queue()

        self._setup_gui()

        if not MY_ADDRESS or MY_ADDRESS == "your_email@gmail.com" or \
           not MY_PASSWORD or MY_PASSWORD == "your_password":
            messagebox.showwarning("Configuration Needed", 
                                   "Please fill in your email credentials (MY_ADDRESS, MY_PASSWORD) at the top of the script.")
            self.connect_button.config(state=tk.DISABLED)
            self.load_more_button.config(state=tk.DISABLED) # Also disable load more if not configured

    def _setup_gui(self):
        # --- Credentials and Connection Frame ---
        cred_frame = ttk.LabelFrame(self.root, text="Connection")
        cred_frame.pack(padx=10, pady=5, fill="x")

        ttk.Label(cred_frame, text="Email:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.email_var = tk.StringVar(value=MY_ADDRESS)
        ttk.Entry(cred_frame, textvariable=self.email_var, width=30, state='readonly').grid(row=0, column=1, padx=5, pady=5)
        
        self.connect_button = ttk.Button(cred_frame, text="Connect & Fetch Self-Sent Mails", command=self.start_connect_and_fetch_thread)
        self.connect_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        
        self.status_var = tk.StringVar(value="Status: Not connected")
        ttk.Label(cred_frame, textvariable=self.status_var).grid(row=0, column=3, padx=5, pady=5, sticky="w", columnspan=2)
        cred_frame.columnconfigure(2, weight=1)

        # --- Fetched Mails Frame ---
        fetched_frame = ttk.LabelFrame(self.root, text="Step 1: Fetched Self-Sent Mails (select one or more)")
        fetched_frame.pack(padx=10, pady=5, fill="both", expand=True)

        listbox_controls_frame = ttk.Frame(fetched_frame)
        listbox_controls_frame.pack(fill="x", pady=(0,5))

        self.load_more_button = ttk.Button(listbox_controls_frame, text="Load/Refresh Initial Batch", command=self.start_connect_and_fetch_thread, state=tk.DISABLED)
        self.load_more_button.pack(side=tk.LEFT, padx=5)
        # Note: The "Load More" functionality is simplified here to re-trigger the initial fetch.
        # A true "Load More" would require managing UIDs and fetching subsequent batches.
        # For now, this button acts as a refresh or initial load if connection was lost.

        listbox_frame = ttk.Frame(fetched_frame)
        listbox_frame.pack(side=tk.LEFT, fill="both", expand=True, padx=5, pady=5)
        self.fetched_mails_listbox = tk.Listbox(listbox_frame, selectmode=tk.EXTENDED, width=70, height=10)
        self.fetched_mails_listbox.pack(side=tk.LEFT, fill="both", expand=True)
        fetched_scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=self.fetched_mails_listbox.yview)
        fetched_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.fetched_mails_listbox.config(yscrollcommand=fetched_scrollbar.set)

        ttk.Button(fetched_frame, text="Add Selected to Editable List ->", command=self.add_selected_to_editable_list).pack(pady=5, padx=5, anchor="center")

        # ... (rest of _setup_gui remains the same as before) ...
        process_frame = ttk.LabelFrame(self.root, text="Step 2: Mails to Process (select an item to edit its details below)")
        process_frame.pack(padx=10, pady=5, fill="both", expand=True)

        columns = ("original_subject", "original_date", "new_sent_date", "new_sender")
        self.editable_treeview = ttk.Treeview(process_frame, columns=columns, show="headings", height=7)
        self.editable_treeview.heading("original_subject", text="Original Subject")
        self.editable_treeview.heading("original_date", text="Original Date")
        self.editable_treeview.heading("new_sent_date", text="New Sent Date (JST)")
        self.editable_treeview.heading("new_sender", text="New Sender")
        self.editable_treeview.column("original_subject", width=250, anchor="w")
        self.editable_treeview.column("original_date", width=180, anchor="w")
        self.editable_treeview.column("new_sent_date", width=200, anchor="w")
        self.editable_treeview.column("new_sender", width=200, anchor="w")
        
        treeview_frame = ttk.Frame(process_frame) 
        treeview_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.editable_treeview.pack(side=tk.LEFT, fill="both", expand=True)
        tree_scrollbar = ttk.Scrollbar(treeview_frame, orient=tk.VERTICAL, command=self.editable_treeview.yview)
        tree_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.editable_treeview.config(yscrollcommand=tree_scrollbar.set)
        self.editable_treeview.bind("<<TreeviewSelect>>", self.on_treeview_select)

        edit_details_frame = ttk.LabelFrame(self.root, text="Step 3: Edit Details for Selected Mail in Treeview")
        edit_details_frame.pack(padx=10, pady=5, fill="x")

        ttk.Label(edit_details_frame, text="New Sent Date (YYYY-MM-DD HH:MM:SS JST):").grid(row=0, column=0, padx=5, pady=3, sticky="w")
        self.new_sent_date_var = tk.StringVar()
        ttk.Entry(edit_details_frame, textvariable=self.new_sent_date_var, width=25).grid(row=0, column=1, padx=5, pady=3, sticky="w")

        ttk.Label(edit_details_frame, text="New Sender ('Display Name <email@example.com>'):").grid(row=1, column=0, padx=5, pady=3, sticky="w")
        self.new_sender_var = tk.StringVar()
        self.sender_combobox = ttk.Combobox(edit_details_frame, textvariable=self.new_sender_var, width=40)
        self.sender_combobox.grid(row=1, column=1, padx=5, pady=3, sticky="w")
        
        save_button = ttk.Button(edit_details_frame, text="Save Details for Selected Item", command=self.save_details_for_selected_item)
        save_button.grid(row=0, column=2, rowspan=2, padx=10, pady=5, sticky="ns")
        
        remove_button = ttk.Button(edit_details_frame, text="Remove Selected from List", command=self.remove_selected_from_editable_list)
        remove_button.grid(row=0, column=3, rowspan=2, padx=10, pady=5, sticky="ns")
        edit_details_frame.columnconfigure(1, weight=1)

        action_frame = ttk.Frame(self.root)
        action_frame.pack(padx=10, pady=10, fill="x")
        self.process_all_button = ttk.Button(action_frame, text="Step 4: Process All Mails in Above List", command=self.start_process_all_mails_thread, state=tk.DISABLED)
        self.process_all_button.pack(pady=5)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.check_queue_periodic() # Start checking the queue

    def _decode_header_value(self, header_value: str) -> str:
        if header_value is None: return ""
        try:
            parts = decode_header(header_value)
            decoded_parts = []
            for part_content, charset in parts:
                if isinstance(part_content, bytes):
                    decoded_parts.append(part_content.decode(charset or 'utf-8', errors='replace'))
                else: 
                    decoded_parts.append(part_content)
            return "".join(decoded_parts)
        except Exception:
            return str(header_value)

    def check_queue_periodic(self):
        """Periodically check the queue for messages from worker threads."""
        try:
            while True: # Process all messages currently in the queue
                message = self.fetch_results_queue.get_nowait()
                
                # Handle different types of messages from the queue
                if isinstance(message, dict):
                    if message.get("type") == "status":
                        self.status_var.set(message["value"])
                    elif message.get("type") == "email_item":
                        self.fetched_mails_listbox.insert(tk.END, message["display_text"])
                        self.fetched_emails_cache.append(message["cache_data"])
                    elif message.get("type") == "fetch_complete":
                        self.status_var.set(message["status_message"])
                        self.connect_button.config(state=tk.NORMAL)
                        self.load_more_button.config(state=tk.NORMAL) # Enable after initial fetch
                        if message.get("error"):
                             messagebox.showerror("Fetch Error", message["error"])
                    elif message.get("type") == "processing_update":
                        self.status_var.set(message["value"])
                    elif message.get("type") == "processing_complete":
                        self.status_var.set(message["status_message"])
                        self.process_all_button.config(state=tk.NORMAL)
                        if message.get("error"):
                            messagebox.showerror("Processing Error", message["error_message"])
                        else:
                            if message.get("summary_message"): # If it was a partial success or full success
                                if message.get("failures_exist"):
                                    messagebox.showwarning("Processing Complete with Errors", message["summary_message"])
                                else:
                                    messagebox.showinfo("Processing Complete", message["summary_message"])
                            self.editable_mails_data.clear()
                            self.refresh_editable_treeview()
                            self.clear_edit_fields()
                            self.process_all_button.config(state=tk.DISABLED if not self.editable_mails_data else tk.NORMAL)


                elif isinstance(message, str) and message == "clear_listbox":
                    self.fetched_mails_listbox.delete(0, tk.END)
                    self.fetched_emails_cache.clear()
                
        except queue.Empty: # No more messages in the queue
            pass
        finally:
            self.root.after(100, self.check_queue_periodic) # Check again after 100ms

    def start_connect_and_fetch_thread(self):
        if not MY_ADDRESS or MY_ADDRESS == "your_email@gmail.com" or not MY_PASSWORD or MY_PASSWORD == "your_password":
            messagebox.showerror("Configuration Error", "MY_ADDRESS or MY_PASSWORD is not set.")
            return

        self.connect_button.config(state=tk.DISABLED)
        self.load_more_button.config(state=tk.DISABLED)
        self.fetch_results_queue.put({"type": "status", "value": "Status: Connecting..."})
        self.fetch_results_queue.put("clear_listbox") # Clear previous results

        # Start the email fetching in a new thread
        thread = threading.Thread(target=self._threaded_fetch_task, daemon=True)
        thread.start()

    def _threaded_fetch_task(self):
        """This function runs in a separate thread to fetch emails."""
        local_client = None # Use a local client instance for this thread
        try:
            local_client = IMAP4_SSL(GMAIL_IMAP_SERVER, GMAIL_IMAP_PORT)
            local_client.login(MY_ADDRESS, MY_PASSWORD)
            self.fetch_results_queue.put({"type": "status", "value": "Status: Connected. Fetching mails..."})

            resp_code, _ = local_client.select(SENT_MAIL_FOLDER, readonly=True)
            if resp_code != 'OK':
                raise Exception(f"Failed to select folder {SENT_MAIL_FOLDER}. Response: {_}")
            
            # Search for all emails in the folder. Filtering for self-sent will happen client-side.
            # This is because FROM is implicit in SENT_MAIL_FOLDER. We need to check TO/CC.
            resp_code, data = local_client.search(None, f'(FROM "{MY_ADDRESS}")')
            if resp_code != 'OK':
                raise Exception(f"Failed to search emails. Response: {data}")
            
            email_uids = data[0].split()
            if not email_uids:
                self.fetch_results_queue.put({
                    "type": "fetch_complete", 
                    "status_message": "Status: No emails found in the folder.",
                    "error": None
                })
                if local_client: local_client.logout()
                return

            num_recent_to_scan = min(len(email_uids), 100) 
            recent_uids_to_scan = email_uids[-num_recent_to_scan:]
            recent_uids_to_scan.reverse() 

            mails_added_count = 0
            i = 1
            for uid_bytes in recent_uids_to_scan:
                resp_code, msg_data = local_client.fetch(uid_bytes, '(RFC822)')
                i += 1
                self.fetch_results_queue.put({"type": "status", "value": f"Status: Fetched {i} mails..."})
                if resp_code != 'OK': continue

                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        
                        from_addr = self._decode_header_value(msg['From'])
                        to_addr = self._decode_header_value(msg['To'])
                        cc_addr = self._decode_header_value(msg['Cc'])

                        is_self_sent = False
                        if MY_ADDRESS in from_addr: # Should always be true in "Sent Mail"
                            if MY_ADDRESS in to_addr or (cc_addr and MY_ADDRESS in cc_addr):
                                is_self_sent = True
                        
                        if not is_self_sent:
                            continue

                        subject = self._decode_header_value(msg['Subject'])
                        date_str = self._decode_header_value(msg['Date']) 

                        display_text = f"Subject: {subject if subject else '(No Subject)'} | Date: {date_str}"
                        cache_item = {
                            "uid": uid_bytes.decode(), 
                            "subject": subject,
                            "date_str": date_str,
                            "email_message_obj": msg 
                        }
                        self.fetch_results_queue.put({"type": "email_item", "display_text": display_text, "cache_data": cache_item})
                        mails_added_count += 1

            final_status = f"Status: Displaying {mails_added_count} recent self-sent emails. Select mails to process."
            if mails_added_count == 0:
                 final_status = f"Status: No recent emails found sent from AND to {MY_ADDRESS} in {SENT_MAIL_FOLDER} (checked last {num_recent_to_scan})."
            
            self.fetch_results_queue.put({
                "type": "fetch_complete", 
                "status_message": final_status,
                "error": None
            })

        except Exception as e:
            error_message = f"Failed to connect or fetch emails: {e}"
            self.fetch_results_queue.put({
                "type": "fetch_complete", 
                "status_message": f"Status: Error - {e}",
                "error": error_message
            })
        finally:
            if local_client:
                try: local_client.logout()
                except: pass
            # The main self.client is established/used by the processing thread.
            # This threaded task only reads.

    def add_selected_to_editable_list(self):
        selected_indices = self.fetched_mails_listbox.curselection()
        if not selected_indices:
            messagebox.showinfo("Info", "No emails selected from the fetched list.")
            return

        added_count = 0
        for index in selected_indices:
            # Ensure index is valid for the current cache size
            if index < 0 or index >= len(self.fetched_emails_cache):
                continue

            cached_email_data = self.fetched_emails_cache[index]
            
            if any(item['uid'] == cached_email_data['uid'] for item in self.editable_mails_data):
                continue 

            self.editable_mails_data.append({
                "uid": cached_email_data['uid'],
                "original_subject": cached_email_data['subject'],
                "original_date_str": cached_email_data['date_str'],
                "original_message_obj": cached_email_data['email_message_obj'],
                "new_sent_date_jst_dt": None, 
                "new_sender_str": None,
            })
            added_count +=1
        
        if added_count > 0:
            self.refresh_editable_treeview()
            self.process_all_button.config(state=tk.NORMAL if self.editable_mails_data else tk.DISABLED)
        else:
            messagebox.showinfo("Info", "Selected email(s) are already in the editable list or selection was invalid.")


    def remove_selected_from_editable_list(self):
        selected_tree_item_ids = self.editable_treeview.selection()
        if not selected_tree_item_ids:
            messagebox.showinfo("Info", "No item selected in the 'Mails to Process' list to remove.")
            return
        uids_to_remove = set(selected_tree_item_ids)
        self.editable_mails_data = [item for item in self.editable_mails_data if item['uid'] not in uids_to_remove]
        self.refresh_editable_treeview()
        self.clear_edit_fields()
        self.process_all_button.config(state=tk.NORMAL if self.editable_mails_data else tk.DISABLED)

    def refresh_editable_treeview(self):
        for item in self.editable_treeview.get_children():
            self.editable_treeview.delete(item)
        for item_data in self.editable_mails_data:
            new_sent_date_display = item_data['new_sent_date_jst_dt'].strftime("%Y-%m-%d %H:%M:%S JST") \
                                    if item_data['new_sent_date_jst_dt'] else "Not set"
            new_sender_display = item_data['new_sender_str'] if item_data['new_sender_str'] else "Not set"
            subj = item_data['original_subject']
            display_subj = (subj[:47] + '...') if len(subj) > 50 else subj
            self.editable_treeview.insert("", tk.END, iid=item_data['uid'], values=(
                display_subj, item_data['original_date_str'], new_sent_date_display, new_sender_display
            ))

    def on_treeview_select(self, event=None):
        selected_item_ids = self.editable_treeview.selection()
        if not selected_item_ids:
            self.clear_edit_fields()
            return
        selected_uid = selected_item_ids[0]
        selected_data = next((item for item in self.editable_mails_data if item['uid'] == selected_uid), None)
        if selected_data:
            if selected_data['new_sent_date_jst_dt']:
                self.new_sent_date_var.set(selected_data['new_sent_date_jst_dt'].strftime("%Y-%m-%d %H:%M:%S"))
            else:
                now_jst = datetime.now(ZoneInfo("Japan"))
                self.new_sent_date_var.set(now_jst.strftime("%Y-%m-%d %H:%M:%S"))
            self.new_sender_var.set(selected_data['new_sender_str'] or "")
            current_combo_values = list(self.sender_history)
            if selected_data['new_sender_str'] and selected_data['new_sender_str'] not in current_combo_values:
                current_combo_values.append(selected_data['new_sender_str'])
            self.sender_combobox['values'] = current_combo_values
        else:
            self.clear_edit_fields()

    def clear_edit_fields(self):
        self.new_sent_date_var.set("")
        self.new_sender_var.set("")

    def save_details_for_selected_item(self):
        selected_item_ids = self.editable_treeview.selection()
        if not selected_item_ids:
            messagebox.showinfo("Info", "No item selected in the 'Mails to Process' list.")
            return
        selected_uid = selected_item_ids[0]
        item_to_update = next((item for item in self.editable_mails_data if item['uid'] == selected_uid), None)
        if not item_to_update:
            messagebox.showerror("Error", "Selected item data not found.")
            return

        date_str = self.new_sent_date_var.get().strip()
        if not date_str:
            messagebox.showerror("Validation Error", "New Sent Date cannot be empty.")
            return
        try:
            naive_dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
            jst_dt = naive_dt.replace(tzinfo=ZoneInfo("Japan"))
        except ValueError:
            messagebox.showerror("Validation Error", "Invalid New Sent Date format. Use YYYY-MM-DD HH:MM:SS.")
            return
        
        sender_str = self.new_sender_var.get().strip()
        if not sender_str:
            messagebox.showerror("Validation Error", "New Sender cannot be empty.")
            return
        if not ("<" in sender_str and ">" in sender_str and "@" in sender_str):
            if not messagebox.askyesno("Sender Format Warning", f"Sender '{sender_str}' doesn't strictly match 'Name <email@addr.com>' format. Continue anyway?"):
                return

        item_to_update['new_sent_date_jst_dt'] = jst_dt
        item_to_update['new_sender_str'] = sender_str
        if sender_str not in self.sender_history:
            self.sender_history.append(sender_str)
            self.sender_combobox['values'] = self.sender_history
        
        self.refresh_editable_treeview()
        if selected_uid in self.editable_treeview.get_children():
             self.editable_treeview.selection_set(selected_uid)
             self.editable_treeview.focus(selected_uid)
        messagebox.showinfo("Success", "Details updated for the selected mail.")

    def start_process_all_mails_thread(self):
        if not self.editable_mails_data:
            messagebox.showinfo("Info", "No mails in the list to process.")
            return

        for item_data in self.editable_mails_data:
            if not item_data['new_sent_date_jst_dt'] or not item_data['new_sender_str']:
                subj_preview = (item_data['original_subject'] or "N/A")[:30]
                messagebox.showerror("Error", f"Mail with subject '{subj_preview}...' is missing new date or sender.")
                return
        
        if not messagebox.askyesno("Confirm Processing", f"Are you sure you want to process {len(self.editable_mails_data)} mail(s)? This will create new emails in your Inbox."):
            return

        self.process_all_button.config(state=tk.DISABLED)
        self.fetch_results_queue.put({"type": "processing_update", "value": f"Status: Processing {len(self.editable_mails_data)} mails..."})
        
        thread = threading.Thread(target=self._threaded_process_task, args=(list(self.editable_mails_data),), daemon=True)
        thread.start()

    def _threaded_process_task(self, mails_to_process_copy):
        """This function runs in a separate thread to process and append emails."""
        # Establish or ensure IMAP client connection for this thread's operations
        if not self.client or self.client.state != 'SELECTED': # A simplified check; Gmail append doesn't need 'SELECTED' state for 'Inbox' usually
            try:
                if self.client: self.client.logout()
            except: pass
            try:
                self.client = IMAP4_SSL(GMAIL_IMAP_SERVER, GMAIL_IMAP_PORT)
                self.client.login(MY_ADDRESS, MY_PASSWORD)
                # For append, selecting a mailbox isn't strictly necessary, but good to have a live client.
                # self.client.select('Inbox') # Optional: select inbox if operations require it
                self.fetch_results_queue.put({"type": "processing_update", "value": "Status: Reconnected. Continuing processing..."})
            except Exception as e_conn:
                self.fetch_results_queue.put({
                    "type": "processing_complete",
                    "status_message": f"Status: Connection error before processing - {e_conn}",
                    "error_message": f"Failed to connect/reconnect: {e_conn}",
                    "summary_message": None
                })
                return
        else: # Check existing connection
             try:
                noop_status, _ = self.client.noop()
                if noop_status != 'OK':
                    raise Exception("IMAP NOOP failed, connection likely stale.")
             except Exception as e_noop:
                try: # Attempt reconnect
                    if self.client: self.client.logout()
                    self.client = IMAP4_SSL(GMAIL_IMAP_SERVER, GMAIL_IMAP_PORT)
                    self.client.login(MY_ADDRESS, MY_PASSWORD)
                    self.fetch_results_queue.put({"type": "processing_update", "value": "Status: Reconnected after NOOP fail. Processing..."})
                except Exception as e_reconn:
                    self.fetch_results_queue.put({
                        "type": "processing_complete",
                        "status_message": f"Status: Reconnect failed - {e_reconn}",
                        "error_message": f"Failed to reconnect after NOOP failure: {e_reconn}",
                        "summary_message": None
                    })
                    return


        processed_count = 0
        failed_items = []

        for item_data in mails_to_process_copy: # Iterate over the copy
            subj_preview = (item_data['original_subject'] or "N/A")[:30]
            try:
                self.fetch_results_queue.put({"type": "processing_update", "value": f"Status: Processing '{subj_preview}...' ({processed_count+1}/{len(mails_to_process_copy)})"})
                
                new_sent_date_jst = item_data['new_sent_date_jst_dt']
                new_received_date = new_sent_date_jst + timedelta(seconds=2) 
                
                create_modified_email(
                    client_obj=self.client, # Use the class's client object
                    target_mailbox='Inbox',
                    new_sent_date_jst=new_sent_date_jst,
                    new_received_date=new_received_date,
                    new_from_header=item_data['new_sender_str'],
                    original_message_obj=item_data['original_message_obj'],
                    my_email_address=MY_ADDRESS
                )
                processed_count += 1
            except Exception as e_item:
                failed_items.append((subj_preview, str(e_item)))
        
        summary_message_str = f"Processed {processed_count} mail(s)."
        failures_exist = bool(failed_items)
        if failed_items:
            summary_message_str += "\n\nFailures:\n" + "\n".join([f"- '{subj}': {err}" for subj, err in failed_items])
        
        self.fetch_results_queue.put({
            "type": "processing_complete",
            "status_message": f"Status: Processing finished. {processed_count} succeeded.",
            "error_message": None, # Global error is None if we reached here
            "summary_message": summary_message_str,
            "failures_exist": failures_exist
        })
        # Note: Clearing editable_mails_data etc. will be handled by the main thread
        # when it processes this "processing_complete" message.

    def on_closing(self):
        if self.client:
            # Try to logout in a separate thread to avoid GUI freeze if network is slow
            def logout_task(client_instance):
                try: client_instance.logout()
                except: pass
            
            logout_thread = threading.Thread(target=logout_task, args=(self.client,), daemon=True)
            logout_thread.start()
            # Give a very short time for logout to initiate, but don't wait indefinitely
            logout_thread.join(timeout=0.5) 
        self.root.destroy()


if __name__ == '__main__':
    if MY_ADDRESS == "your_email@gmail.com" or MY_PASSWORD == "your_password":
        print("CRITICAL ERROR: Email credentials are not set in the script.")
        print("Please edit the script and fill in MY_ADDRESS and MY_PASSWORD.")
        try:
            root_check = tk.Tk()
            root_check.withdraw()
            messagebox.showerror("Configuration Error", 
                                 "Email credentials (MY_ADDRESS, MY_PASSWORD) are not set.\n"
                                 "Please edit the script to configure them.")
            root_check.destroy()
        except tk.TclError: 
            pass
        exit(1)

    main_root = tk.Tk()
    app = EmailProcessorApp(main_root)
    main_root.mainloop()
