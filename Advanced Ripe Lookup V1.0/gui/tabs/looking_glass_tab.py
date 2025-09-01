import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Extracted from AdvancedRIPEIPLookup for modular UI.
# This function expects 'app' to be an instance of AdvancedRIPEIPLookup (or compatible).

def create_looking_glass_tab(self):

        self.lg_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.lg_tab, text="Looking Glass")
        self.lg_ip = tk.StringVar()
        input_frame = tk.LabelFrame(self.lg_tab, text="Looking Glass Query", padx=5, pady=5)
        input_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(input_frame, text="IP Address/Range:").grid(row=0, column=0, sticky="w")
        tk.Entry(input_frame, textvariable=self.lg_ip, width=30).grid(row=0, column=1)
        self.lg_query_button = tk.Button(input_frame, text="Query", command=self.query_looking_glass)
        self.lg_query_button.grid(row=0, column=2)
        result_frame = tk.LabelFrame(self.lg_tab, text="Looking Glass Results", padx=5, pady=5)
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        lg_scroll_y = ttk.Scrollbar(result_frame)
        lg_scroll_y.pack(side="right", fill="y")
        lg_scroll_x = ttk.Scrollbar(result_frame, orient="horizontal")
        lg_scroll_x.pack(side="bottom", fill="x")
        self.lg_tree = ttk.Treeview(result_frame, yscrollcommand=lg_scroll_y.set, xscrollcommand=lg_scroll_x.set)
        self.lg_tree.pack(fill="both", expand=True)
        lg_scroll_y.config(command=self.lg_tree.yview)
        lg_scroll_x.config(command=self.lg_tree.xview)
        lg_columns = ["location", "peer", "prefix", "asn_origin", "as_path", "last_as", "community", "last_updated"]
        self.lg_tree["columns"] = lg_columns
        self.lg_tree.column("#0", width=0, stretch=tk.NO)
        for col in lg_columns:
            self.lg_tree.column(col, width=120, anchor="w", minwidth=50, stretch=tk.YES)
            self.lg_tree.heading(col, text=col.replace("_", " ").title())
        button_frame = tk.Frame(self.lg_tab)
        button_frame.pack(fill="x", padx=10, pady=5)
        self.lg_export_button = tk.Button(button_frame, text="Export to Excel", command=self.export_lg_to_excel)
        self.lg_export_button.pack(side="left", padx=5)
        self.location_colors = {}
        self.as_path_tags = {}
        tk.Label(self.lg_tab, text="Log").pack(anchor="w", padx=10)
        self.lg_log = tk.Text(self.lg_tab, height=8, state="disabled")
        self.lg_log.pack(fill="x", padx=10, pady=5)
