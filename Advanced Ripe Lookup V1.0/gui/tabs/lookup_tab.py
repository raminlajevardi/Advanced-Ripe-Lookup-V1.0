import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Extracted from AdvancedRIPEIPLookup for modular UI.
# This function expects 'app' to be an instance of AdvancedRIPEIPLookup (or compatible).

def create_lookup_tab(self):

        self.lookup_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.lookup_tab, text="RIPE Lookup")
        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.single_ip = tk.StringVar()
        file_frame = tk.LabelFrame(self.lookup_tab, text="File Input", padx=5, pady=5)
        file_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(file_frame, text="Input File (Excel/Text):").grid(row=0, column=0, sticky="w")
        tk.Entry(file_frame, textvariable=self.input_file, width=50).grid(row=0, column=1)
        tk.Button(file_frame, text="Browse", command=self.browse_input_file).grid(row=0, column=2)
        tk.Label(file_frame, text="Output File (Excel):").grid(row=1, column=0, sticky="w")
        tk.Entry(file_frame, textvariable=self.output_file, width=50).grid(row=1, column=1)
        tk.Button(file_frame, text="Browse", command=self.browse_output_file).grid(row=1, column=2)
        single_frame = tk.LabelFrame(self.lookup_tab, text="Ripe Lookup", padx=5, pady=5)
        single_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(single_frame, text="IP Address/Range:").grid(row=0, column=0, sticky="w")
        tk.Entry(single_frame, textvariable=self.single_ip, width=30).grid(row=0, column=1)
        tk.Button(single_frame, text="Lookup", command=self.lookup_single_ip).grid(row=0, column=2)
        result_frame = tk.LabelFrame(self.lookup_tab, text="Results", padx=5, pady=5)
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        scroll_y = ttk.Scrollbar(result_frame)
        scroll_y.pack(side="right", fill="y")
        scroll_x = ttk.Scrollbar(result_frame, orient="horizontal")
        scroll_x.pack(side="bottom", fill="x")
        self.tree = ttk.Treeview(result_frame, yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.tree.pack(fill="both", expand=True)
        self.tree.tag_configure('has_route', background='white')
        self.tree.tag_configure('no_route', background='#d4edda')
        scroll_y.config(command=self.tree.yview)
        scroll_x.config(command=self.tree.xview)
        button_frame = tk.Frame(self.lookup_tab)
        button_frame.pack(fill="x", padx=10, pady=5)
        tk.Button(button_frame, text="Process File", command=self.process_file).pack(side="left", padx=5)
        tk.Button(button_frame, text="Export to Excel", command=self.export_to_excel).pack(side="left", padx=5)
        tk.Button(button_frame, text="Clear Results", command=self.clear_results).pack(side="left", padx=5)
        self.configure_treeview()
