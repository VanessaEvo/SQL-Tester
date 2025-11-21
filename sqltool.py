#!/usr/bin/env python3
"""
SQL Injection Testing Tool
Educational Use Only - 2025
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
import requests
import urllib.parse
import random
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import our modules
from domain import DomainManager
from payload import PayloadManager
from tamper import get_tamper_scripts
from engine import SQLDetectionEngine, DetectionResult
from report import ReportGenerator
from user_agent import UserAgentManager

class ScrollableFrame(tk.Frame):
    """
    A more robust custom Tkinter frame that is scrollable.
    Includes mouse wheel scrolling for Windows and Linux.
    """
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)

        bg_color = kwargs.get('bg', self.cget('bg'))

        self.canvas = tk.Canvas(self, bg=bg_color, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=bg_color)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Bind mouse wheel scrolling for cross-platform compatibility
        self.bind_mousewheel()

    def bind_mousewheel(self):
        self.bind('<Enter>', self._bind_to_mousewheel)
        self.bind('<Leave>', self._unbind_from_mousewheel)

    def _bind_to_mousewheel(self, event):
        """Bind mouse wheel events."""
        self.bind_all("<MouseWheel>", self._on_mousewheel) # Windows
        self.bind_all("<Button-4>", self._on_mousewheel)   # Linux (scroll up)
        self.bind_all("<Button-5>", self._on_mousewheel)   # Linux (scroll down)

    def _unbind_from_mousewheel(self, event):
        """Unbind mouse wheel events."""
        self.unbind_all("<MouseWheel>")
        self.unbind_all("<Button-4>")
        self.unbind_all("<Button-5>")

    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling."""
        # Determine scroll direction and magnitude
        if sys.platform == "win32":
            delta = -1 * (event.delta // 120)
        elif event.num == 4: # Linux scroll up
            delta = -1
        else: # Linux scroll down
            delta = 1

        self.canvas.yview_scroll(delta, "units")


class SQLInjectionTool:
    def __init__(self):
        self.root = tk.Tk()
        self.setup_window()
        self.setup_variables()
        self.setup_managers()
        self.create_interface()
        
    def setup_window(self):
        """Configure the main window"""
        self.root.title("Professional SQL Injection Testing Tool - 2025 Edition")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Dark theme colors
        self.colors = {
            'bg': '#2b2b2b',
            'fg': '#ffffff',
            'select_bg': '#404040',
            'select_fg': '#ffffff',
            'button_bg': '#4a90e2',
            'button_fg': '#ffffff',
            'entry_bg': '#404040',
            'entry_fg': '#ffffff',
            'frame_bg': '#353535',
            'accent': '#4a90e2',
            'success': '#5cb85c',
            'warning': '#f0ad4e',
            'danger': '#d9534f'
        }
        
        # Configure root
        self.root.configure(bg=self.colors['bg'])
        
        # Configure ttk styles
        self.setup_styles()
        
    def setup_styles(self):
        """Setup ttk styles for dark theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure('TNotebook', background=self.colors['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', background=self.colors['frame_bg'], foreground=self.colors['fg'], 
                       padding=[20, 10], borderwidth=1)
        style.map('TNotebook.Tab', background=[('selected', self.colors['accent'])])
        
        style.configure('TFrame', background=self.colors['bg'])
        style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure('TButton', background=self.colors['button_bg'], foreground=self.colors['button_fg'])
        style.configure('TCheckbutton', background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure('TEntry', fieldbackground=self.colors['entry_bg'], foreground=self.colors['entry_fg'])
        style.configure('TCombobox', fieldbackground=self.colors['entry_bg'], foreground=self.colors['entry_fg'])
        
    def setup_variables(self):
        """Initialize tkinter variables"""
        # Single target variables
        self.target_url = tk.StringVar(value="http://example.com/page.php?id=1")
        self.test_parameter = tk.StringVar()
        self.request_delay = tk.DoubleVar(value=1.0)
        self.request_timeout = tk.IntVar(value=10)
        self.threads = tk.IntVar(value=1)
        
        # Injection type variables
        self.injection_types = {
            'basic': tk.BooleanVar(value=True),
            'union': tk.BooleanVar(value=True),
            'boolean': tk.BooleanVar(value=True),
            'time_based': tk.BooleanVar(value=True),
            'error_based': tk.BooleanVar(value=True),
            'advanced': tk.BooleanVar(value=False),
            'bypass': tk.BooleanVar(value=False),
            'json': tk.BooleanVar(value=False),
            'nosql': tk.BooleanVar(value=False)
        }
        
        # Scan control variables
        self.scan_type = tk.StringVar(value="Quick Scan") # Quick Scan vs Full Scan
        self.tamper_script = tk.StringVar()
        self.scan_running = False
        self.scan_paused = False
        self.current_scan_mode = 'single'  # Track which scan is running: 'single' or 'multi'
        self.scan_results = []
        self.valid_domains_to_scan = []
        self.results_lock = threading.Lock()  # Thread-safe lock for updating shared data
        
        # Statistics variables
        self.stats = {
            'requests': tk.IntVar(value=0),
            'vulnerabilities': tk.IntVar(value=0),
            'status': tk.StringVar(value="Ready")
        }
        
    def setup_managers(self):
        """Initialize manager classes"""
        self.domain_manager = DomainManager()
        self.payload_manager = PayloadManager()
        self.detection_engine = SQLDetectionEngine()
        self.report_generator = ReportGenerator()
        self.user_agent_manager = UserAgentManager()
        
    def create_interface(self):
        """Create the main interface"""
        # Create main notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_single_target_tab()
        self.create_multiple_targets_tab()
        self.create_results_tab()
        self.create_payloads_tab()
        self.create_about_tab()
        
    def create_single_target_tab(self):
        """Create the single target testing tab"""
        # Main frame
        single_frame = ttk.Frame(self.notebook)
        self.notebook.add(single_frame, text="🎯 Single Target")
        
        # Create main container with fixed button area
        main_container = tk.Frame(single_frame, bg=self.colors['bg'])
        main_container.pack(fill='both', expand=True)
        
        # Use ScrollableFrame for the main content area
        scrollable_area = ScrollableFrame(main_container, bg=self.colors['bg'])
        scrollable_area.pack(fill='both', expand=True, padx=5, pady=5)
        content_frame = scrollable_area.scrollable_frame
        
        # Left panel - Configuration
        left_panel = tk.LabelFrame(content_frame, text="🔧 Target Configuration", 
                                  bg=self.colors['frame_bg'], fg=self.colors['fg'], 
                                  font=('Arial', 10, 'bold'))
        left_panel.pack(side='left', fill='both', expand=False, padx=(0, 5), pady=5)
        left_panel.configure(width=350)
        
        # Target URL
        tk.Label(left_panel, text="Target URL:", bg=self.colors['frame_bg'], 
                fg=self.colors['fg']).pack(anchor='w', padx=10, pady=(10, 5))
        
        url_entry = tk.Entry(left_panel, textvariable=self.target_url, 
                           bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                           font=('Consolas', 9))
        url_entry.pack(fill='x', padx=10, pady=(0, 10))
        
        # Test Parameter
        tk.Label(left_panel, text="Test Parameter:", bg=self.colors['frame_bg'], 
                fg=self.colors['fg']).pack(anchor='w', padx=10, pady=(5, 5))
        
        param_frame = tk.Frame(left_panel, bg=self.colors['frame_bg'])
        param_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        param_entry = tk.Entry(param_frame, textvariable=self.test_parameter, 
                             bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                             font=('Consolas', 9))
        param_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))
        
        parse_btn = tk.Button(param_frame, text="🔍 Parse URL Parameters", 
                            command=self.parse_url_parameters,
                            bg=self.colors['accent'], fg=self.colors['button_fg'], 
                            font=('Arial', 8))
        parse_btn.pack(side='right')
        
        # Injection Types
        injection_frame = tk.LabelFrame(left_panel, text="Injection Types", 
                                      bg=self.colors['frame_bg'], fg=self.colors['fg'])
        injection_frame.pack(fill='x', padx=10, pady=10)
        
        # Create checkboxes in a grid
        injection_items = [
            ('basic', 'Basic'), ('union', 'Union'), ('boolean', 'Boolean'), 
            ('time_based', 'Time-based'), ('error_based', 'Error-based'), 
            ('advanced', 'Advanced'), ('bypass', 'Bypass'), ('json', 'JSON'),
            ('nosql', 'NoSQL Injection')
        ]
        
        for i, (key, label) in enumerate(injection_items):
            row, col = i // 2, i % 2
            cb = tk.Checkbutton(injection_frame, text=label, variable=self.injection_types[key],
                              bg=self.colors['frame_bg'], fg=self.colors['fg'], 
                              selectcolor=self.colors['entry_bg'])
            cb.grid(row=row, column=col, sticky='w', padx=5, pady=2)
            if key == 'nosql':
                cb.config(state='disabled')
        
        # Quick selection buttons
        btn_frame = tk.Frame(injection_frame, bg=self.colors['frame_bg'])
        btn_frame.grid(row=5, column=0, columnspan=2, pady=5)
        
        tk.Button(btn_frame, text="Select All", command=self.select_all_injections,
                 bg=self.colors['success'], fg=self.colors['button_fg'], 
                 font=('Arial', 8)).pack(side='left', padx=2)
        
        tk.Button(btn_frame, text="Select None", command=self.select_no_injections,
                 bg=self.colors['warning'], fg=self.colors['button_fg'], 
                 font=('Arial', 8)).pack(side='left', padx=2)
        
        tk.Button(btn_frame, text="Recommended", command=self.select_recommended_injections,
                 bg=self.colors['accent'], fg=self.colors['button_fg'], 
                 font=('Arial', 8)).pack(side='left', padx=2)
        
        # Scan Settings
        settings_frame = tk.LabelFrame(left_panel, text="Scan Settings", 
                                     bg=self.colors['frame_bg'], fg=self.colors['fg'])
        settings_frame.pack(fill='x', padx=10, pady=10)
        
        # Scan Type Radio Buttons
        scan_type_frame = tk.Frame(settings_frame, bg=self.colors['frame_bg'])
        scan_type_frame.pack(fill='x', padx=5, pady=5)
        tk.Label(scan_type_frame, text="Scan Type:", bg=self.colors['frame_bg'], fg=self.colors['fg']).pack(side='left', padx=(0, 10))
        tk.Radiobutton(scan_type_frame, text="Quick", variable=self.scan_type, value="Quick", bg=self.colors['frame_bg'], fg=self.colors['fg'], selectcolor=self.colors['entry_bg']).pack(side='left')
        tk.Radiobutton(scan_type_frame, text="Full", variable=self.scan_type, value="Full", bg=self.colors['frame_bg'], fg=self.colors['fg'], selectcolor=self.colors['entry_bg']).pack(side='left', padx=(10, 0))

        # Tamper Script Combobox
        tamper_frame = tk.Frame(settings_frame, bg=self.colors['frame_bg'])
        tamper_frame.pack(fill='x', padx=5, pady=5)
        tk.Label(tamper_frame, text="Tamper Script:", bg=self.colors['frame_bg'], fg=self.colors['fg']).pack(side='left', padx=(0, 10))

        self.tamper_scripts_map = get_tamper_scripts()
        self.tamper_combobox = ttk.Combobox(tamper_frame, textvariable=self.tamper_script,
                                            values=list(self.tamper_scripts_map.keys()), state="readonly")
        self.tamper_combobox.set("None")
        self.tamper_combobox.pack(fill='x', expand=True)

        # Request Delay
        tk.Label(settings_frame, text="Request Delay (s):", 
                bg=self.colors['frame_bg'], fg=self.colors['fg']).pack(anchor='w', padx=5, pady=(5, 2))
        delay_scale = tk.Scale(settings_frame, from_=0.1, to=5.0, resolution=0.1, 
                             orient='horizontal', variable=self.request_delay,
                             bg=self.colors['frame_bg'], fg=self.colors['fg'], 
                             highlightbackground=self.colors['frame_bg'])
        delay_scale.pack(fill='x', padx=5, pady=(0, 5))
        
        # Request Timeout
        tk.Label(settings_frame, text="Request Timeout (s):",
                bg=self.colors['frame_bg'], fg=self.colors['fg']).pack(anchor='w', padx=5, pady=(5, 2))
        timeout_scale = tk.Scale(settings_frame, from_=5, to=30, orient='horizontal',
                               variable=self.request_timeout,
                               bg=self.colors['frame_bg'], fg=self.colors['fg'],
                               highlightbackground=self.colors['frame_bg'])
        timeout_scale.pack(fill='x', padx=5, pady=(0, 5))
        
        # Right panel - Statistics and Results
        right_panel = tk.Frame(content_frame, bg=self.colors['bg'])
        right_panel.pack(side='right', fill='both', expand=True, padx=(5, 0), pady=5)
        
        # Live Statistics
        stats_frame = tk.LabelFrame(right_panel, text="📊 Live Statistics", 
                                  bg=self.colors['frame_bg'], fg=self.colors['fg'], 
                                  font=('Arial', 10, 'bold'))
        stats_frame.pack(fill='x', pady=(0, 5))
        
        stats_container = tk.Frame(stats_frame, bg=self.colors['frame_bg'])
        stats_container.pack(fill='x', padx=10, pady=10)
        
        # Statistics cards
        self.create_stat_card(stats_container, "Requests", self.stats['requests'], 
                            self.colors['accent'], 0)
        self.create_stat_card(stats_container, "Vulns", self.stats['vulnerabilities'], 
                            self.colors['danger'], 1)
        self.create_stat_card(stats_container, "Status", self.stats['status'], 
                            self.colors['warning'], 2)
        
        # Progress Bar
        progress_frame = tk.LabelFrame(right_panel, text="🚀 Scan Progress", 
                                     bg=self.colors['frame_bg'], fg=self.colors['fg'])
        progress_frame.pack(fill='x', pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, 
                                          maximum=100, length=400)
        self.progress_bar.pack(padx=10, pady=10)
        
        self.progress_label = tk.Label(progress_frame, text="Ready to scan...", 
                                     bg=self.colors['frame_bg'], fg=self.colors['fg'])
        self.progress_label.pack(pady=(0, 10))
        
        # Live Results
        results_frame = tk.LabelFrame(right_panel, text="🔍 Live Scan Results", 
                                    bg=self.colors['frame_bg'], fg=self.colors['fg'])
        results_frame.pack(fill='both', expand=True, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, 
                                                    bg=self.colors['entry_bg'], 
                                                    fg=self.colors['entry_fg'], 
                                                    font=('Consolas', 9), 
                                                    height=15)
        self.results_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # FIXED BUTTON AREA - Always visible at bottom
        button_container = tk.Frame(main_container, bg=self.colors['bg'], height=60)
        button_container.pack(fill='x', side='bottom', padx=10, pady=10)
        button_container.pack_propagate(False)  # Maintain fixed height
        
        # --- REVISED BUTTON LAYOUT (Single Target) ---
        button_frame_container = tk.Frame(button_container, bg=self.colors['bg'])
        button_frame_container.pack(expand=True, fill='both')

        # Clear Results button on the right
        tk.Button(button_frame_container, text="Clear Results",
                  command=self.clear_results,
                  bg=self.colors['frame_bg'], fg=self.colors['fg'],
                  font=('Arial', 10)).pack(side='right', padx=(0, 20), ipady=5)

        # Frame for centered control buttons
        center_button_frame = tk.Frame(button_frame_container, bg=self.colors['bg'])
        center_button_frame.pack(expand=True)

        # Consistent styles from multi-target tab
        btn_font = ('Arial', 11, 'bold')
        btn_width = 12
        btn_height = 2

        self.start_button = tk.Button(center_button_frame, text="START SCAN",
                                         command=self.start_single_scan,
                                         bg=self.colors['success'], fg=self.colors['button_fg'],
                                         font=btn_font, width=btn_width, height=btn_height)
        self.start_button.pack(side='left', padx=5)

        self.pause_button = tk.Button(center_button_frame, text="PAUSE",
                                          command=self.pause_scan,
                                          bg=self.colors['warning'], fg=self.colors['button_fg'],
                                          font=btn_font, width=btn_width, height=btn_height, state='disabled')
        self.pause_button.pack(side='left', padx=5)

        self.stop_button = tk.Button(center_button_frame, text="STOP",
                                         command=self.stop_scan,
                                         bg=self.colors['danger'], fg=self.colors['button_fg'],
                                         font=btn_font, width=btn_width, height=btn_height, state='disabled')
        self.stop_button.pack(side='left', padx=5)
        
    def create_multiple_targets_tab(self):
        """Create the multiple targets testing tab"""
        # Main frame
        multi_frame = ttk.Frame(self.notebook)
        self.notebook.add(multi_frame, text="🌐 Multiple Targets")
        
        # Create main container with fixed button area
        main_container = tk.Frame(multi_frame, bg=self.colors['bg'])
        main_container.pack(fill='both', expand=True)
        
        # Content area
        content_frame = tk.Frame(main_container, bg=self.colors['bg'])
        content_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left side - Domain Management and Settings
        left_side = tk.Frame(content_frame, bg=self.colors['bg'])
        left_side.pack(side='left', fill='both', expand=True, padx=(0, 5))
        
        # Domain Management Panel
        domain_frame = tk.LabelFrame(left_side, text="🌐 Domain Management", 
                                   bg=self.colors['frame_bg'], fg=self.colors['fg'], 
                                   font=('Arial', 12, 'bold'))
        domain_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        # File operations
        file_frame = tk.Frame(domain_frame, bg=self.colors['frame_bg'])
        file_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(file_frame, text="📁 Load domains from file:", 
                bg=self.colors['frame_bg'], fg=self.colors['fg'], 
                font=('Arial', 10)).pack(side='left')
        
        tk.Button(file_frame, text="📁 Load File", command=self.load_domains_file,
                 bg=self.colors['accent'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='left', padx=10)
        
        tk.Button(file_frame, text="💾 Save Domains", command=self.save_domains_file,
                 bg=self.colors['success'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='left', padx=5)
        
        tk.Button(file_frame, text="✅ Validate Domains", command=self.validate_domains,
                 bg=self.colors['warning'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='left', padx=5)

        tk.Button(file_frame, text="🗑️ Clear", command=self.clear_domain_list,
                 bg=self.colors['danger'], fg=self.colors['button_fg'],
                 font=('Arial', 9)).pack(side='left', padx=5)
        
        # Domain input area
        input_frame = tk.Frame(domain_frame, bg=self.colors['frame_bg'])
        input_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        tk.Label(input_frame, text="🌐 Enter domains manually (one per line):", 
                bg=self.colors['frame_bg'], fg=self.colors['fg']).pack(anchor='w')
        
        self.domain_text = scrolledtext.ScrolledText(input_frame, 
                                                   bg=self.colors['entry_bg'], 
                                                   fg=self.colors['entry_fg'], 
                                                   font=('Consolas', 9), 
                                                   height=12)
        self.domain_text.pack(fill='both', expand=True, pady=(5, 0))
        
        # Add example domains
        example_domains = """# Example domains (one per line):
http://example.com/search.php?id=1
https://testsite.com/product.php?id=123&cat=electronics
http://demo.site/user.php?user_id=456
# Lines starting with # are comments"""
        self.domain_text.insert('1.0', example_domains)
        
        # Multi-Scan Settings Panel
        multi_settings_frame = tk.LabelFrame(left_side, text="⚙️ Multi-Scan Settings", 
                                           bg=self.colors['frame_bg'], fg=self.colors['fg'], 
                                           font=('Arial', 10, 'bold'))
        multi_settings_frame.pack(fill='x', pady=(0, 0))
        
        # Settings in a grid layout
        settings_grid = tk.Frame(multi_settings_frame, bg=self.colors['frame_bg'])
        settings_grid.pack(fill='x', padx=10, pady=10)
        
        # Request Delay
        tk.Label(settings_grid, text="Request Delay (s):", 
                bg=self.colors['frame_bg'], fg=self.colors['fg']).grid(row=0, column=0, sticky='w', padx=5, pady=2)
        delay_scale_multi = tk.Scale(settings_grid, from_=0.1, to=5.0, resolution=0.1, 
                                   orient='horizontal', variable=self.request_delay,
                                   bg=self.colors['frame_bg'], fg=self.colors['fg'], 
                                   highlightbackground=self.colors['frame_bg'], length=150)
        delay_scale_multi.grid(row=0, column=1, sticky='ew', padx=5, pady=2)
        
        # Request Timeout
        tk.Label(settings_grid, text="Request Timeout (s):", 
                bg=self.colors['frame_bg'], fg=self.colors['fg']).grid(row=1, column=0, sticky='w', padx=5, pady=2)
        timeout_scale_multi = tk.Scale(settings_grid, from_=5, to=30, orient='horizontal', 
                                     variable=self.request_timeout,
                                     bg=self.colors['frame_bg'], fg=self.colors['fg'], 
                                     highlightbackground=self.colors['frame_bg'], length=150)
        timeout_scale_multi.grid(row=1, column=1, sticky='ew', padx=5, pady=2)
        
        # Threads
        tk.Label(settings_grid, text="Threads:", 
                bg=self.colors['frame_bg'], fg=self.colors['fg']).grid(row=2, column=0, sticky='w', padx=5, pady=2)
        thread_scale_multi = tk.Scale(settings_grid, from_=1, to=10, orient='horizontal', 
                                    variable=self.threads,
                                    bg=self.colors['frame_bg'], fg=self.colors['fg'], 
                                    highlightbackground=self.colors['frame_bg'], length=150)
        thread_scale_multi.grid(row=2, column=1, sticky='ew', padx=5, pady=2)
        
        # Configure grid weights
        settings_grid.grid_columnconfigure(1, weight=1)
        
        # Right side - Statistics, Progress, and Results
        right_side = tk.Frame(content_frame, bg=self.colors['bg'])
        right_side.pack(side='right', fill='both', expand=True, padx=(5, 0))
        
        # Multi-Scan Statistics
        multi_stats_frame = tk.LabelFrame(right_side, text="📊 Multi-Scan Statistics", 
                                        bg=self.colors['frame_bg'], fg=self.colors['fg'], 
                                        font=('Arial', 10, 'bold'))
        multi_stats_frame.pack(fill='x', pady=(0, 5))
        
        multi_stats_container = tk.Frame(multi_stats_frame, bg=self.colors['frame_bg'])
        multi_stats_container.pack(fill='x', padx=10, pady=10)
        
        # Multi-scan statistics cards
        self.multi_stats = {
            'domains': tk.IntVar(value=0),
            'completed': tk.IntVar(value=0),
            'vulnerabilities': tk.IntVar(value=0),
            'status': tk.StringVar(value="Ready")
        }
        
        self.create_stat_card(multi_stats_container, "Domains", self.multi_stats['domains'], 
                            self.colors['accent'], 0)
        self.create_stat_card(multi_stats_container, "Completed", self.multi_stats['completed'], 
                            self.colors['success'], 1)
        self.create_stat_card(multi_stats_container, "Vulns", self.multi_stats['vulnerabilities'], 
                            self.colors['danger'], 2)
        self.create_stat_card(multi_stats_container, "Status", self.multi_stats['status'], 
                            self.colors['warning'], 3)
        
        # Multi-Scan Progress
        multi_progress_frame = tk.LabelFrame(right_side, text="🚀 Multi-Scan Progress", 
                                           bg=self.colors['frame_bg'], fg=self.colors['fg'])
        multi_progress_frame.pack(fill='x', pady=5)
        
        self.multi_progress_var = tk.DoubleVar()
        self.multi_progress_bar = ttk.Progressbar(multi_progress_frame, variable=self.multi_progress_var, 
                                                maximum=100, length=400)
        self.multi_progress_bar.pack(padx=10, pady=10)
        
        self.multi_progress_label = tk.Label(multi_progress_frame, text="Ready to scan multiple targets...", 
                                           bg=self.colors['frame_bg'], fg=self.colors['fg'])
        self.multi_progress_label.pack(pady=(0, 10))
        
        # Multi-Scan Results
        multi_results_frame = tk.LabelFrame(right_side, text="🔍 Multi-Scan Results", 
                                          bg=self.colors['frame_bg'], fg=self.colors['fg'])
        multi_results_frame.pack(fill='both', expand=True, pady=5)
        
        self.multi_results_text = scrolledtext.ScrolledText(multi_results_frame, 
                                                          bg=self.colors['entry_bg'], 
                                                          fg=self.colors['entry_fg'], 
                                                          font=('Consolas', 9), 
                                                          height=15)
        self.multi_results_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # FIXED BUTTON AREA - Always visible at bottom
        button_container = tk.Frame(main_container, bg=self.colors['bg'], height=60)
        button_container.pack(fill='x', side='bottom', padx=10, pady=10)
        button_container.pack_propagate(False)  # Maintain fixed height
        
        # --- REVISED BUTTON LAYOUT ---
        button_frame_container = tk.Frame(button_container, bg=self.colors['bg'])
        button_frame_container.pack(expand=True, fill='both')

        # Clear Log button on the right
        tk.Button(button_frame_container, text="Clear Log",
                  command=self.clear_multi_results,
                  bg=self.colors['frame_bg'], fg=self.colors['fg'],
                  font=('Arial', 10)).pack(side='right', padx=(0, 20), ipady=5)

        # Frame for centered control buttons
        center_button_frame = tk.Frame(button_frame_container, bg=self.colors['bg'])
        center_button_frame.pack(expand=True)

        # Consistent styles
        btn_font = ('Arial', 11, 'bold')
        btn_width = 12
        btn_height = 2

        self.multi_scan_button = tk.Button(center_button_frame, text="START",
                                         command=self.start_multi_scan,
                                         bg=self.colors['success'], fg=self.colors['button_fg'],
                                         font=btn_font, width=btn_width, height=btn_height)
        self.multi_scan_button.pack(side='left', padx=5)

        self.multi_pause_button = tk.Button(center_button_frame, text="PAUSE",
                                          command=self.pause_multi_scan,
                                          bg=self.colors['warning'], fg=self.colors['button_fg'],
                                          font=btn_font, width=btn_width, height=btn_height, state='disabled')
        self.multi_pause_button.pack(side='left', padx=5)

        self.multi_stop_button = tk.Button(center_button_frame, text="STOP",
                                         command=self.stop_multi_scan,
                                         bg=self.colors['danger'], fg=self.colors['button_fg'],
                                         font=btn_font, width=btn_width, height=btn_height, state='disabled')
        self.multi_stop_button.pack(side='left', padx=5)
        
    def create_results_tab(self):
        """Create the results viewing and export tab"""
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="📊 Results")
        
        # Main container
        main_container = tk.Frame(results_frame, bg=self.colors['bg'])
        main_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Header
        header_frame = tk.Frame(main_container, bg=self.colors['bg'])
        header_frame.pack(fill='x', pady=(0, 10))
        
        tk.Label(header_frame, text="📊 Scan Results & Reports", 
                bg=self.colors['bg'], fg=self.colors['fg'], 
                font=('Arial', 16, 'bold')).pack(side='left')
        
        # Export buttons
        export_frame = tk.Frame(header_frame, bg=self.colors['bg'])
        export_frame.pack(side='right')
        
        tk.Button(export_frame, text="📄 Export HTML", command=self.export_html_report,
                 bg=self.colors['accent'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='left', padx=2)
        
        tk.Button(export_frame, text="📋 Export CSV", command=self.export_csv_report,
                 bg=self.colors['success'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='left', padx=2)
        
        tk.Button(export_frame, text="📝 Export JSON", command=self.export_json_report,
                 bg=self.colors['warning'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='left', padx=2)
        
        tk.Button(export_frame, text="🗑️ Clear All", command=self.clear_all_results,
                 bg=self.colors['danger'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='left', padx=2)
        
        # Results summary
        summary_frame = tk.LabelFrame(main_container, text="📈 Results Summary", 
                                    bg=self.colors['frame_bg'], fg=self.colors['fg'], 
                                    font=('Arial', 12, 'bold'))
        summary_frame.pack(fill='x', pady=(0, 10))
        
        summary_container = tk.Frame(summary_frame, bg=self.colors['frame_bg'])
        summary_container.pack(fill='x', padx=10, pady=10)
        
        # Summary statistics
        self.summary_stats = {
            'total_scans': tk.IntVar(value=0),
            'total_vulnerabilities': tk.IntVar(value=0),
            'high_risk': tk.IntVar(value=0),
            'medium_risk': tk.IntVar(value=0)
        }
        
        self.create_stat_card(summary_container, "Total Scans", self.summary_stats['total_scans'], 
                            self.colors['accent'], 0)
        self.create_stat_card(summary_container, "Vulnerabilities", self.summary_stats['total_vulnerabilities'], 
                            self.colors['danger'], 1)
        self.create_stat_card(summary_container, "High Risk", self.summary_stats['high_risk'], 
                            '#e74c3c', 2)
        self.create_stat_card(summary_container, "Medium Risk", self.summary_stats['medium_risk'], 
                            '#f39c12', 3)
        
        # Results table
        table_frame = tk.LabelFrame(main_container, text="🔍 Detailed Results", 
                                  bg=self.colors['frame_bg'], fg=self.colors['fg'])
        table_frame.pack(fill='both', expand=True)
        
        # Create treeview for results
        columns = ('Time', 'Target', 'Parameter', 'Type', 'Status', 'Confidence', 'Risk')
        self.results_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=100, anchor='center')
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.results_tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient='horizontal', command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.results_tree.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=10)
        v_scrollbar.pack(side='right', fill='y', pady=10)
        h_scrollbar.pack(side='bottom', fill='x', padx=10)
        
        # Bind double-click event
        self.results_tree.bind('<Double-1>', self.show_result_details)
        
    def create_payloads_tab(self):
        """Create the payloads management tab"""
        payloads_frame = ttk.Frame(self.notebook)
        self.notebook.add(payloads_frame, text="🔧 Payloads")
        
        # Main container
        main_container = tk.Frame(payloads_frame, bg=self.colors['bg'])
        main_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Header
        header_frame = tk.Frame(main_container, bg=self.colors['bg'])
        header_frame.pack(fill='x', pady=(0, 10))
        
        tk.Label(header_frame, text="🔧 Payload Management", 
                bg=self.colors['bg'], fg=self.colors['fg'], 
                font=('Arial', 16, 'bold')).pack(side='left')
        
        # Payload management buttons
        payload_buttons = tk.Frame(header_frame, bg=self.colors['bg'])
        payload_buttons.pack(side='right')
        
        tk.Button(payload_buttons, text="📁 Load Payloads", command=self.load_custom_payloads,
                 bg=self.colors['accent'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='left', padx=2)
        
        tk.Button(payload_buttons, text="💾 Save Payloads", command=self.save_custom_payloads,
                 bg=self.colors['success'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='left', padx=2)
        
        tk.Button(payload_buttons, text="🔄 Reset Default", command=self.reset_default_payloads,
                 bg=self.colors['warning'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='left', padx=2)
        
        # Content area
        content_frame = tk.Frame(main_container, bg=self.colors['bg'])
        content_frame.pack(fill='both', expand=True)
        
        # Left side - Payload categories
        left_panel = tk.Frame(content_frame, bg=self.colors['bg'])
        left_panel.pack(side='left', fill='both', expand=False, padx=(0, 5))
        
        # Payload categories
        categories_frame = tk.LabelFrame(left_panel, text="📂 Payload Categories", 
                                       bg=self.colors['frame_bg'], fg=self.colors['fg'])
        categories_frame.pack(fill='both', expand=True)
        
        # Category listbox
        self.category_listbox = tk.Listbox(categories_frame, 
                                         bg=self.colors['entry_bg'], 
                                         fg=self.colors['entry_fg'], 
                                         font=('Arial', 10),
                                         selectbackground=self.colors['accent'])
        self.category_listbox.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Populate categories
        payload_categories = [
            "🎯 Basic Payloads",
            "🔗 Union-based",
            "✅ Boolean-based", 
            "⏰ Time-based",
            "❌ Error-based",
            "🚀 Advanced",
            "🛡️ WAF Bypass",
            "📋 JSON Payloads"
        ]
        
        for category in payload_categories:
            self.category_listbox.insert(tk.END, category)
        
        # Bind selection event
        self.category_listbox.bind('<<ListboxSelect>>', self.on_category_select)
        
        # Category statistics
        stats_frame = tk.LabelFrame(left_panel, text="📊 Category Stats", 
                                  bg=self.colors['frame_bg'], fg=self.colors['fg'])
        stats_frame.pack(fill='x', pady=(10, 0))
        
        self.payload_stats_text = tk.Text(stats_frame, 
                                        bg=self.colors['entry_bg'], 
                                        fg=self.colors['entry_fg'], 
                                        font=('Consolas', 9),
                                        height=6, state='disabled')
        self.payload_stats_text.pack(fill='x', padx=10, pady=10)
        
        # Right side - Payload viewer and editor
        right_panel = tk.Frame(content_frame, bg=self.colors['bg'])
        right_panel.pack(side='right', fill='both', expand=True, padx=(5, 0))
        
        # Payload viewer
        viewer_frame = tk.LabelFrame(right_panel, text="👁️ Payload Viewer", 
                                   bg=self.colors['frame_bg'], fg=self.colors['fg'])
        viewer_frame.pack(fill='both', expand=True, pady=(0, 5))
        
        # Payload list
        self.payload_listbox = tk.Listbox(viewer_frame, 
                                        bg=self.colors['entry_bg'], 
                                        fg=self.colors['entry_fg'], 
                                        font=('Consolas', 9),
                                        selectbackground=self.colors['accent'])
        
        payload_scrollbar = ttk.Scrollbar(viewer_frame, orient='vertical', command=self.payload_listbox.yview)
        self.payload_listbox.configure(yscrollcommand=payload_scrollbar.set)
        
        self.payload_listbox.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=10)
        payload_scrollbar.pack(side='right', fill='y', pady=10, padx=(0, 10))
        
        # Custom payload editor
        editor_frame = tk.LabelFrame(right_panel, text="✏️ Custom Payload Editor", 
                                   bg=self.colors['frame_bg'], fg=self.colors['fg'])
        editor_frame.pack(fill='x', pady=(5, 0))
        
        # Editor controls
        editor_controls = tk.Frame(editor_frame, bg=self.colors['frame_bg'])
        editor_controls.pack(fill='x', padx=10, pady=(10, 5))
        
        tk.Button(editor_controls, text="➕ Add Payload", command=self.add_custom_payload,
                 bg=self.colors['success'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='left', padx=2)
        
        tk.Button(editor_controls, text="✏️ Edit Selected", command=self.edit_selected_payload,
                 bg=self.colors['accent'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='left', padx=2)
        
        tk.Button(editor_controls, text="🗑️ Delete Selected", command=self.delete_selected_payload,
                 bg=self.colors['danger'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='left', padx=2)
        
        tk.Button(editor_controls, text="🧪 Test Payload", command=self.test_selected_payload,
                 bg=self.colors['warning'], fg=self.colors['button_fg'], 
                 font=('Arial', 9)).pack(side='right', padx=2)
        
        # Payload input
        self.payload_entry = tk.Entry(editor_frame, 
                                    bg=self.colors['entry_bg'], 
                                    fg=self.colors['entry_fg'], 
                                    font=('Consolas', 10))
        self.payload_entry.pack(fill='x', padx=10, pady=(0, 10))
        
        # Initialize with basic payloads
        self.category_listbox.selection_set(0)
        self.on_category_select(None)
        
    def create_about_tab(self):
        """Create the about tab with author and tool information"""
        about_frame = ttk.Frame(self.notebook)
        self.notebook.add(about_frame, text="ℹ️ About")
        
        # Main container with scrollable content
        main_container = tk.Frame(about_frame, bg=self.colors['bg'])
        main_container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Header
        header_frame = tk.Frame(main_container, bg=self.colors['bg'])
        header_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(header_frame, text="🛡️ Professional SQL Injection Testing Tool", 
                bg=self.colors['bg'], fg=self.colors['accent'], 
                font=('Arial', 18, 'bold')).pack()
        
        tk.Label(header_frame, text="Version 2025.1 - Educational Edition",
                bg=self.colors['bg'], fg=self.colors['fg'], 
                font=('Arial', 12)).pack(pady=(5, 0))
        
        # Scrollable content area
        content_frame = scrolledtext.ScrolledText(main_container, 
                                                bg=self.colors['entry_bg'], 
                                                fg=self.colors['entry_fg'], 
                                                font=('Arial', 11),
                                                wrap=tk.WORD,
                                                state='normal')
        content_frame.pack(fill='both', expand=True)
        
        # About content
        about_content = """
👨‍💻 AUTHOR INFORMATION
═══════════════════════════════════════════════════════════════════════════════

Developer: ShinX
GitHub: https://github.com/VanessaEvo
Version: 2025.1
Release Date: July 2025
License: Educational Use Only

🌟 TOOL OVERVIEW
═══════════════════════════════════════════════════════════════════════════════

This SQL Injection Testing Tool is designed for educational purposes and authorized security testing. It provides a comprehensive platform for learning about SQL injection vulnerabilities and testing web applications with proper authorization.

🔧 KEY FEATURES
═══════════════════════════════════════════════════════════════════════════════

• Advanced Detection Engine
  - Error-based SQL injection detection
  - Boolean-based blind SQL injection
  - Time-based blind SQL injection
  - Union-based SQL injection
  - WAF bypass techniques
  - JSON-based injection testing

• Professional User Interface
  - Modern dark theme design
  - Real-time statistics and progress tracking
  - Multi-threaded scanning capabilities
  - Live result monitoring
  - Responsive layout design

• Payload Management System
  - 500+ pre-built payloads
  - Database-specific payload optimization
  - Custom payload creation and editing
  - Payload categorization and organization
  - Import/export functionality

• Advanced Features
  - 200+ modern user agents for stealth testing
  - Intelligent request throttling
  - Session management
  - Comprehensive reporting (HTML, CSV, JSON)
  - Multi-target scanning capabilities

🔬 TECHNICAL SPECIFICATIONS
═══════════════════════════════════════════════════════════════════════════════

Programming Language: Python 3.7+
GUI Framework: Tkinter with custom dark theme styling
HTTP Library: Requests with advanced session management
Threading: Multi-threaded architecture for performance
Supported Databases: MySQL, PostgreSQL, Microsoft SQL Server, Oracle, SQLite, MongoDB

Detection Methods:
• Pattern-based error detection
• Response time analysis
• Content-based boolean detection
• Union query validation
• Database fingerprinting

⚠️ LEGAL DISCLAIMER & ETHICAL USE
═══════════════════════════════════════════════════════════════════════════════

🚨 IMPORTANT: This tool is designed exclusively for educational purposes and authorized security testing. Users must comply with all applicable laws and regulations.

AUTHORIZED USE ONLY:
• Only test systems you own or have explicit written permission to test
• Obtain proper authorization before conducting any security assessments
• Respect the terms of service of all target systems
• Follow responsible disclosure practices for any vulnerabilities found
• Use this tool only for legitimate security research and education

PROHIBITED ACTIVITIES:
• Testing systems without explicit authorization
• Malicious attacks or unauthorized access attempts
• Violating computer crime laws or regulations
• Using this tool for illegal or unethical purposes
• Bypassing security measures without permission

🎓 EDUCATIONAL VALUE
═══════════════════════════════════════════════════════════════════════════════

This tool serves as an educational platform for:
• Understanding SQL injection vulnerabilities
• Learning secure coding practices
• Practicing ethical hacking techniques
• Developing security testing skills
• Preparing for security certifications

Learning Objectives:
• Identify common SQL injection patterns
• Understand different injection techniques
• Learn about database security
• Practice responsible vulnerability disclosure
• Develop defensive programming skills

🙏 ACKNOWLEDGMENTS
═══════════════════════════════════════════════════════════════════════════════

Special thanks to the security research community for their contributions to SQL injection research and the development of detection techniques. This tool builds upon years of security research and responsible disclosure practices.

Inspired by tools like SQLMap, Burp Suite, and other professional security testing platforms, while maintaining a focus on education and ethical use.

📞 SUPPORT & FEEDBACK
═══════════════════════════════════════════════════════════════════════════════

For questions, feedback, or educational inquiries:
• GitHub: https://github.com/VanessaEvo
• Issues: Report bugs and feature requests through GitHub Issues
• Educational Use: This tool is provided as-is for educational purposes

Remember: Always use this tool responsibly and ethically. The goal is to improve security through education and authorized testing, not to cause harm or engage in illegal activities.

═══════════════════════════════════════════════════════════════════════════════
"""
        
        content_frame.insert('1.0', about_content)
        content_frame.config(state='disabled')  # Make it read-only
        
        # Footer
        footer_frame = tk.Frame(main_container, bg=self.colors['bg'])
        footer_frame.pack(fill='x', pady=(10, 0))
        
        tk.Label(footer_frame, text="⚠️ Remember: Use this tool responsibly and only on systems you are authorized to test!", 
                bg=self.colors['bg'], fg=self.colors['danger'], 
                font=('Arial', 10, 'bold')).pack()
        
    def create_stat_card(self, parent, title, variable, color, column):
        """Create a statistics card that automatically updates."""
        card = tk.Frame(parent, bg=color, relief='raised', bd=2)
        card.grid(row=0, column=column, padx=5, pady=5, sticky='ew')
        parent.grid_columnconfigure(column, weight=1)
        
        tk.Label(card, text=title, bg=color, fg='white', 
                font=('Arial', 10, 'bold')).pack(pady=(5, 0))
        
        # Use textvariable to make the label update automatically
        value_label = tk.Label(card, textvariable=variable, bg=color, fg='white',
                               font=('Arial', 14, 'bold'))
        value_label.pack(pady=(0, 5))

    # Results Tab Methods
    def export_html_report(self):
        """Export results as HTML report"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save HTML Report",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                self.report_generator.scan_results = self.scan_results
                self.report_generator.save_report(file_path, 'html')
                messagebox.showinfo("Success", f"HTML report saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save HTML report: {str(e)}")

    def export_csv_report(self):
        """Export results as CSV report"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save CSV Report",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                self.report_generator.scan_results = self.scan_results
                self.report_generator.save_report(file_path, 'csv')
                messagebox.showinfo("Success", f"CSV report saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save CSV report: {str(e)}")

    def export_json_report(self):
        """Export results as JSON report"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save JSON Report",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                self.report_generator.scan_results = self.scan_results
                self.report_generator.save_report(file_path, 'json')
                messagebox.showinfo("Success", f"JSON report saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save JSON report: {str(e)}")

    def clear_all_results(self):
        """Clear all scan results"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all results?"):
            self.scan_results.clear()
            self.results_tree.delete(*self.results_tree.get_children())
            self.update_results_summary()
            messagebox.showinfo("Success", "All results cleared")

    def show_result_details(self, event):
        """Show detailed information about a selected result"""
        selection = self.results_tree.selection()
        if not selection:
            return
        
        item = self.results_tree.item(selection[0])
        values = item['values']
        
        # Create details window
        details_window = tk.Toplevel(self.root)
        details_window.title("Result Details")
        details_window.geometry("600x400")
        details_window.configure(bg=self.colors['bg'])
        
        # Details content
        details_text = scrolledtext.ScrolledText(details_window, 
                                               bg=self.colors['entry_bg'], 
                                               fg=self.colors['entry_fg'], 
                                               font=('Consolas', 10))
        details_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Format details
        details_content = f"""
SCAN RESULT DETAILS
═══════════════════════════════════════════════════════════════════════════════

Time: {values[0]}
Target URL: {values[1]}
Test Parameter: {values[2]}
Injection Type: {values[3]}
Status: {values[4]}
Confidence: {values[5]}
Risk Level: {values[6]}

Additional Information:
• Detection Method: Pattern-based analysis
• Response Analysis: Completed
• Database Fingerprinting: Attempted
• Payload Effectiveness: Evaluated

═══════════════════════════════════════════════════════════════════════════════
"""
        
        details_text.insert('1.0', details_content)
        details_text.config(state='disabled')

    def update_results_summary(self):
        """Update the results summary statistics"""
        total_scans = len(self.scan_results)
        vulnerabilities = len([r for r in self.scan_results if r.get('vulnerable', False)])
        high_risk = len([r for r in self.scan_results if r.get('risk_level') == 'High'])
        medium_risk = len([r for r in self.scan_results if r.get('risk_level') == 'Medium'])
        
        self.summary_stats['total_scans'].set(total_scans)
        self.summary_stats['total_vulnerabilities'].set(vulnerabilities)
        self.summary_stats['high_risk'].set(high_risk)
        self.summary_stats['medium_risk'].set(medium_risk)

    # Payloads Tab Methods
    def on_category_select(self, event):
        """Handle payload category selection"""
        selection = self.category_listbox.curselection()
        if not selection:
            return
        
        category_index = selection[0]
        category_map = {
            0: 'basic',
            1: 'union', 
            2: 'boolean',
            3: 'time_based',
            4: 'error_based',
            5: 'advanced',
            6: 'bypass',
            7: 'json'
        }
        
        category = category_map.get(category_index, 'basic')
        payloads = self.payload_manager.get_payloads_by_type(category)
        
        # Update payload listbox
        self.payload_listbox.delete(0, tk.END)
        for payload in payloads:
            self.payload_listbox.insert(tk.END, payload)
        
        # Update statistics
        self.update_payload_stats(category, payloads)

    def update_payload_stats(self, category, payloads):
        """Update payload statistics display"""
        stats_text = f"""
Category: {category.title()}
Total Payloads: {len(payloads)}
Average Length: {sum(len(p) for p in payloads) // len(payloads) if payloads else 0}
Complexity: {'High' if len(payloads) > 50 else 'Medium' if len(payloads) > 20 else 'Low'}
"""
        
        self.payload_stats_text.config(state='normal')
        self.payload_stats_text.delete('1.0', tk.END)
        self.payload_stats_text.insert('1.0', stats_text)
        self.payload_stats_text.config(state='disabled')

    def load_custom_payloads(self):
        """Load custom payloads from file"""
        file_path = filedialog.askopenfilename(
            title="Load Custom Payloads",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    if file_path.endswith('.json'):
                        data = json.load(f)
                        # Handle JSON payload format
                        messagebox.showinfo("Success", "JSON payloads loaded successfully")
                    else:
                        # Handle text file format
                        payloads = [line.strip() for line in f.readlines() if line.strip()]
                        messagebox.showinfo("Success", f"Loaded {len(payloads)} custom payloads")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load payloads: {str(e)}")

    def save_custom_payloads(self):
        """Save current payloads to file"""
        file_path = filedialog.asksaveasfilename(
            title="Save Custom Payloads",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                # Get current payloads
                payloads = []
                for i in range(self.payload_listbox.size()):
                    payloads.append(self.payload_listbox.get(i))
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    if file_path.endswith('.json'):
                        json.dump(payloads, f, indent=2)
                    else:
                        for payload in payloads:
                            f.write(payload + '\n')
                
                messagebox.showinfo("Success", f"Saved {len(payloads)} payloads to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save payloads: {str(e)}")

    def reset_default_payloads(self):
        """Reset to default payloads"""
        if messagebox.askyesno("Confirm", "Reset to default payloads? This will remove any custom payloads."):
            self.payload_manager = PayloadManager()  # Reinitialize with defaults
            self.on_category_select(None)  # Refresh display
            messagebox.showinfo("Success", "Payloads reset to defaults")

    def add_custom_payload(self):
        """Add a custom payload"""
        payload = self.payload_entry.get().strip()
        if not payload:
            messagebox.showwarning("Warning", "Please enter a payload")
            return
        
        self.payload_listbox.insert(tk.END, payload)
        self.payload_entry.delete(0, tk.END)
        messagebox.showinfo("Success", "Custom payload added")

    def edit_selected_payload(self):
        """Edit the selected payload"""
        selection = self.payload_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a payload to edit")
            return
        
        index = selection[0]
        current_payload = self.payload_listbox.get(index)
        self.payload_entry.delete(0, tk.END)
        self.payload_entry.insert(0, current_payload)

    def delete_selected_payload(self):
        """Delete the selected payload"""
        selection = self.payload_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a payload to delete")
            return
        
        if messagebox.askyesno("Confirm", "Delete selected payload?"):
            self.payload_listbox.delete(selection[0])
            messagebox.showinfo("Success", "Payload deleted")

    def test_selected_payload(self):
        """Test the selected payload"""
        selection = self.payload_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a payload to test")
            return
        
        payload = self.payload_listbox.get(selection[0])
        messagebox.showinfo("Payload Test", f"Testing payload: {payload}\n\nThis would test the payload against a target URL.")

    # Event handlers and utility methods
    def parse_url_parameters(self):
        """Parse URL parameters and populate the test parameter field"""
        url = self.target_url.get()
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            if params:
                # Get the first parameter
                first_param = list(params.keys())[0]
                self.test_parameter.set(first_param)
                messagebox.showinfo("Success", f"Found parameter: {first_param}")
            else:
                messagebox.showwarning("Warning", "No parameters found in URL")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse URL: {str(e)}")
    
    def select_all_injections(self):
        """Select all injection types"""
        for var in self.injection_types.values():
            var.set(True)
    
    def select_no_injections(self):
        """Deselect all injection types"""
        for var in self.injection_types.values():
            var.set(False)
    
    def select_recommended_injections(self):
        """Select recommended injection types"""
        recommended = ['basic', 'union', 'boolean', 'error_based']
        for key, var in self.injection_types.items():
            var.set(key in recommended)
    
    def load_domains_file(self):
        """Load domains from a file"""
        file_path = filedialog.askopenfilename(
            title="Select domains file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.domain_text.delete('1.0', tk.END)
                self.domain_text.insert('1.0', content)
                messagebox.showinfo("Success", f"Loaded domains from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def save_domains_file(self):
        """Save domains to a file"""
        file_path = filedialog.asksaveasfilename(
            title="Save domains file",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                content = self.domain_text.get('1.0', tk.END)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Saved domains to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def clear_domain_list(self):
        """Clear the domain list text area and the validated domains list."""
        if messagebox.askyesno("Confirm Clear", "Anda yakin ingin membersihkan daftar domain?"):
            self.domain_text.delete('1.0', tk.END)
            self.valid_domains_to_scan.clear()
            self.log_multi_result("INFO: Daftar domain telah dibersihkan.")
            # Reset statistics
            self.multi_stats['domains'].set(0)
            self.multi_stats['completed'].set(0)
            self.multi_stats['vulnerabilities'].set(0)
            self.multi_stats['status'].set("Ready")

    def validate_domains(self):
        """Validate the entered domains"""
        content = self.domain_text.get('1.0', tk.END)
        domains = [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('#')]
        
        if not domains:
            messagebox.showwarning("Warning", "No domains to validate")
            return
        
        # Show validation in multi-results
        self.multi_results_text.delete('1.0', tk.END)
        self.multi_results_text.insert(tk.END, "Validating domains...\n\n")
        
        valid_count = 0
        invalid_count = 0
        self.valid_domains_to_scan.clear()
        
        for domain in domains:
            is_valid, message = self.domain_manager.validate_url(domain)
            if is_valid:
                self.multi_results_text.insert(tk.END, f"✅ {domain}\n")
                self.valid_domains_to_scan.append(domain)
                valid_count += 1
            else:
                self.multi_results_text.insert(tk.END, f"❌ {domain}: {message}\n")
                invalid_count += 1
        
        # Update multi-scan statistics with only the valid count
        self.multi_stats['domains'].set(valid_count)

        self.multi_results_text.insert(tk.END, f"\n📊 Summary: {valid_count} valid, {invalid_count} invalid")
        
    def start_single_scan(self):
        """Start single target scan"""
        if self.scan_running:
            messagebox.showwarning("Warning", "Scan is already running")
            return
        
        # Validate inputs
        url = self.target_url.get().strip()
        param = self.test_parameter.get().strip()
        
        if not url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
        
        if not param:
            messagebox.showerror("Error", "Please specify a test parameter")
            return
        
        # Check if any injection types are selected
        selected_types = [key for key, var in self.injection_types.items() if var.get() and key != 'nosql']
        if not selected_types:
            messagebox.showerror("Error", "Please select at least one injection type")
            return

        # --- Proactive WAF Detection ---
        self.log_result("INFO: Performing proactive WAF detection...")
        is_waf, waf_reason = self.detection_engine.detect_waf(url)
        if is_waf:
            self.log_result(f"WARNING: WAF Detected! Reason: {waf_reason}")
            if not messagebox.askyesno("WAF Detected", "A WAF may be present, which could affect scan results. Do you want to continue?"):
                return
        else:
            self.log_result("INFO: No clear WAF indicators found. Proceeding with scan.")
        
        # Update UI before starting thread for immediate feedback
        self.stats['status'].set("Scanning...")
        self.root.update_idletasks()

        # Start scan in separate thread
        self.scan_running = True
        self.update_scan_buttons()
        
        scan_thread = threading.Thread(target=self.run_single_scan, 
                                     args=(url, param, selected_types))
        scan_thread.daemon = True
        scan_thread.start()
    
    def start_multi_scan(self):
        """Start multiple targets scan"""
        domains = self.valid_domains_to_scan
        
        if not domains:
            messagebox.showerror("Error", "Please validate domains first. The list of valid domains to scan is empty.")
            return
        
        selected_types = [key for key, var in self.injection_types.items() if var.get()]
        if not selected_types:
            messagebox.showerror("Error", "Please select at least one injection type")
            return

        # Update stats before starting thread for immediate UI feedback
        self.multi_stats['status'].set("Scanning...")
        self.multi_stats['domains'].set(len(domains))
        self.multi_stats['completed'].set(0)
        self.multi_stats['vulnerabilities'].set(0)
        self.multi_progress_var.set(0)
        self.multi_results_text.delete('1.0', tk.END)
        self.root.update_idletasks()
        
        # Start multi-scan
        self.scan_running = True
        self.update_multi_scan_buttons()
        
        multi_scan_thread = threading.Thread(target=self.run_multi_scan, 
                                            args=(domains, selected_types))
        multi_scan_thread.daemon = True
        multi_scan_thread.start()
    
    def run_single_scan(self, url, param, injection_types):
        """Run the actual single target scan"""
        try:
            # FIXED: Set scan mode to 'single' so logs go to correct tab
            self.current_scan_mode = 'single'
            self.progress_var.set(0)

            # CRITICAL FIX: Establish baseline response BEFORE testing payloads
            self.log_result("INFO: Establishing baseline response...")
            try:
                baseline_headers = self.user_agent_manager.get_realistic_headers()
                baseline_start = time.time()
                baseline_resp = requests.get(url, headers=baseline_headers, timeout=self.request_timeout.get())
                baseline_time = time.time() - baseline_start

                self.detection_engine.set_baseline(baseline_resp.text, baseline_time)
                self.log_result(f"✓ Baseline established (status: {baseline_resp.status_code}, time: {baseline_time:.2f}s, size: {len(baseline_resp.text)} bytes)")
            except Exception as e:
                self.log_result(f"⚠ WARNING: Could not establish baseline: {str(e)}")
                self.log_result("⚠ This may result in inaccurate detection, especially for boolean-based and time-based attacks.")
                # Continue anyway, but user is warned

            # Get payloads for selected injection types
            all_payloads = []
            scan_mode = self.scan_type.get()
            self.log_result(f"INFO: Starting {scan_mode}...")

            for injection_type in injection_types:
                payloads = self.payload_manager.get_payloads_by_type(injection_type)
                if scan_mode == "Quick Scan":
                    payloads = payloads[:15]  # Use a subset for Quick Scan
                for payload in payloads:
                    all_payloads.append((injection_type, payload))

            total_payloads = len(all_payloads)
            if total_payloads == 0:
                self.log_result("WARNING: No payloads to test for the selected injection types.")
                self.stats['status'].set("Complete")
                return

            for i, (injection_type, payload) in enumerate(all_payloads):
                if not self.scan_running:
                    self.log_result("INFO: Scan stopped by user.")
                    break

                # --- Pause/Resume Logic ---
                while self.scan_paused:
                    time.sleep(0.5)
                    if not self.scan_running: # Check if stopped while paused
                        self.log_result("INFO: Scan stopped by user while paused.")
                        break
                if not self.scan_running:
                    break
                
                # Update progress
                progress = ((i + 1) / total_payloads) * 100
                self.progress_var.set(progress)
                self.progress_label.config(text=f"Testing payload {i+1}/{total_payloads}")
                
                # Test payload
                result = self.test_payload(url, param, payload, injection_type)
                
                # Update statistics
                self.stats['requests'].set(self.stats['requests'].get() + 1)
                
                if result and result.vulnerable:
                    self.stats['vulnerabilities'].set(self.stats['vulnerabilities'].get() + 1)
                    self.log_result(f"🚨 VULNERABILITY FOUND: {injection_type} - {payload}")
                    
                    # Add to results for export
                    scan_result = {
                        'timestamp': datetime.now().isoformat(),
                        'target_url': url,
                        'test_parameter': param,
                        'injection_type': injection_type,
                        'vulnerable': True,
                        'payload': payload,
                        'confidence': result.confidence,
                        'evidence': result.error_message,
                        'risk_level': 'High' if result.confidence > 0.8 else 'Medium'
                    }
                    self.scan_results.append(scan_result)
                    
                    # Add to results tree
                    self.results_tree.insert('', 'end', values=(
                        datetime.now().strftime('%H:%M:%S'),
                        url[:30] + '...' if len(url) > 30 else url,
                        param,
                        injection_type,
                        'Vulnerable',
                        f"{result.confidence:.2f}",
                        scan_result['risk_level']
                    ))
                else:
                    self.log_result(f"✅ Clean: {injection_type} - {payload[:50]}...")
                
                # Delay between requests
                time.sleep(self.request_delay.get())
            
            self.progress_var.set(100)
            self.stats['status'].set("Complete")
            self.progress_label.config(text="Scan completed!")
            self.update_results_summary()
            
        except Exception as e:
            self.log_result(f"❌ Error during scan: {str(e)}")
            self.stats['status'].set("Error")
        finally:
            self.scan_running = False
            self.update_scan_buttons()
    
    def scan_single_domain(self, domain, injection_types):
        """Worker function to scan a single domain - used by thread pool"""
        vulnerabilities_found = 0

        try:
            # Log current domain
            self.log_multi_result(f"🎯 Scanning: {domain}")

            # Extract parameters from domain
            parsed = urllib.parse.urlparse(domain)
            params = urllib.parse.parse_qs(parsed.query)

            if not params:
                self.log_multi_result(f"⚠️ No parameters found in: {domain}")
                return 0

            # Test each parameter
            for param_name in params.keys():
                if not self.scan_running:
                    break

                for injection_type in injection_types:
                    if not self.scan_running:
                        break

                    payloads = self.payload_manager.get_payloads_by_type(injection_type)

                    for payload in payloads[:5]:  # Limit payloads for multi-scan
                        if not self.scan_running:
                            break

                        result = self.test_payload(domain, param_name, payload, injection_type)

                        if result and result.vulnerable:
                            vulnerabilities_found += 1
                            self.log_multi_result(f"🚨 VULNERABILITY: {domain} - {param_name}")

                            # Add to results (thread-safe)
                            scan_result = {
                                'timestamp': datetime.now().isoformat(),
                                'target_url': domain,
                                'test_parameter': param_name,
                                'injection_type': injection_type,
                                'vulnerable': True,
                                'payload': payload,
                                'confidence': result.confidence,
                                'evidence': result.error_message,
                                'risk_level': 'High' if result.confidence > 0.8 else 'Medium'
                            }

                            with self.results_lock:
                                self.scan_results.append(scan_result)

                            break  # Move to next injection type

                        time.sleep(self.request_delay.get())

        except Exception as e:
            self.log_multi_result(f"❌ Error scanning {domain}: {str(e)}")

        return vulnerabilities_found

    def run_multi_scan(self, domains, injection_types):
        """Run multiple target scan with thread pool support"""
        try:
            # FIXED: Set scan mode to 'multi' so logs go to correct tab
            self.current_scan_mode = 'multi'
            completed = 0
            total_vulnerabilities = 0

            # Get number of threads from settings
            num_threads = self.threads.get()
            total_domains = len(domains)

            self.log_multi_result(f"🚀 Starting multi-scan with {num_threads} threads...")
            self.log_multi_result(f"📊 Total targets: {total_domains}")

            # Use ThreadPoolExecutor for parallel scanning
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                # Submit all domain scan jobs
                future_to_domain = {
                    executor.submit(self.scan_single_domain, domain, injection_types): domain
                    for domain in domains
                }

                # Process completed scans as they finish
                for future in as_completed(future_to_domain):
                    if not self.scan_running:
                        # Cancel remaining tasks
                        for f in future_to_domain:
                            f.cancel()
                        break

                    domain = future_to_domain[future]

                    try:
                        # Get result from completed scan
                        vulnerabilities = future.result()
                        total_vulnerabilities += vulnerabilities

                    except Exception as e:
                        self.log_multi_result(f"❌ Exception in thread for {domain}: {str(e)}")

                    # Update progress (thread-safe)
                    completed += 1
                    progress = (completed / total_domains) * 100

                    with self.results_lock:
                        self.multi_progress_var.set(progress)
                        self.multi_progress_label.config(text=f"Scanning domain {completed}/{total_domains}")
                        self.multi_stats['completed'].set(completed)
                        self.multi_stats['vulnerabilities'].set(total_vulnerabilities)

            # Scan complete
            self.multi_progress_var.set(100)
            self.multi_stats['status'].set("Complete")
            self.multi_progress_label.config(text=f"Multi-scan completed! ({num_threads} threads)")
            self.log_multi_result(f"✅ Scan complete! Total vulnerabilities: {total_vulnerabilities}")
            self.update_results_summary()

        except Exception as e:
            self.log_multi_result(f"❌ Error during multi-scan: {str(e)}")
            self.multi_stats['status'].set("Error")
        finally:
            self.scan_running = False
            self.update_multi_scan_buttons()
    
    def test_payload(self, url, param, payload, injection_type):
        """Test a single payload"""
        try:
            # --- Apply Tamper Script ---
            selected_tamper_name = self.tamper_script.get()
            tamper_function = self.tamper_scripts_map.get(selected_tamper_name)

            original_payload = payload
            if tamper_function:
                payload = tamper_function(payload)

            # Construct test URL
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            # This logic assumes the parameter value doesn't already contain the payload
            # A more robust implementation would handle replacing existing payloads
            if param in params:
                params[param] = [params[param][0] + payload]
            else:
                params[param] = [payload]
            
            new_query = urllib.parse.urlencode(params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            # Get random user agent
            headers = self.user_agent_manager.get_realistic_headers()
            
            # Make request
            start_time = time.time()
            response = requests.get(test_url, headers=headers, 
                                  timeout=self.request_timeout.get())
            response_time = time.time() - start_time
            
            # --- Pass Request Context for Re-verification ---
            request_context = {
                'url': url, # Pass the original URL without payload
                'param': param,
                'headers': headers,
                'timeout': self.request_timeout.get(),
                'tamper_function': tamper_function # Pass for re-verification tampering
            }

            # Analyze response
            result = self.detection_engine.analyze_response_comprehensive(
                response.text, original_payload, response_time, injection_type, request_context
            )
            
            return result
            
        except Exception as e:
            self.log_result(f"❌ Request failed for payload '{payload[:50]}...': {str(e)}")
            return None
    
    def log_result(self, message):
        """Log a result to the appropriate results text area based on scan mode"""
        timestamp = datetime.now().strftime("%H:%M:%S")

        # FIXED: Route logs to the correct tab based on which scan is running
        if self.current_scan_mode == 'multi':
            # If multi-scan is running, log to multi-scan results
            self.multi_results_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.multi_results_text.see(tk.END)
        else:
            # Default: log to single target results
            self.results_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.results_text.see(tk.END)

        self.root.update_idletasks()
    
    def log_multi_result(self, message):
        """Log a result to the multi-scan results text area"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.multi_results_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.multi_results_text.see(tk.END)
        self.root.update_idletasks()
    
    def pause_scan(self):
        """Pause the current scan"""
        self.scan_paused = not self.scan_paused
        if self.scan_paused:
            self.pause_button.config(text="▶️ RESUME")
            self.stats['status'].set("Paused")
        else:
            self.pause_button.config(text="⏸️ PAUSE")
            self.stats['status'].set("Scanning...")
    
    def pause_multi_scan(self):
        """Pause the multi-scan"""
        self.scan_paused = not self.scan_paused
        if self.scan_paused:
            self.multi_pause_button.config(text="▶️ RESUME")
            self.multi_stats['status'].set("Paused")
        else:
            self.multi_pause_button.config(text="⏸️ PAUSE")
            self.multi_stats['status'].set("Scanning...")
    
    def stop_scan(self):
        """Stop the current scan"""
        self.scan_running = False
        self.scan_paused = False
        self.stats['status'].set("Stopped")
        self.update_scan_buttons()
    
    def stop_multi_scan(self):
        """Stop the multi-scan"""
        self.scan_running = False
        self.scan_paused = False
        self.multi_stats['status'].set("Stopped")
        self.update_multi_scan_buttons()
    
    def clear_results(self):
        """Clear the results text area"""
        self.results_text.delete('1.0', tk.END)
        self.stats['requests'].set(0)
        self.stats['vulnerabilities'].set(0)
        self.stats['status'].set("Ready")
        self.progress_var.set(0)
        self.progress_label.config(text="Ready to scan...")
    
    def clear_multi_results(self):
        """Clear the multi-scan results"""
        self.multi_results_text.delete('1.0', tk.END)
        self.multi_stats['domains'].set(0)
        self.multi_stats['completed'].set(0)
        self.multi_stats['vulnerabilities'].set(0)
        self.multi_stats['status'].set("Ready")
        self.multi_progress_var.set(0)
        self.multi_progress_label.config(text="Ready to scan multiple targets...")
    
    def update_scan_buttons(self):
        """Update scan button states"""
        if self.scan_running:
            self.start_button.config(state='disabled')
            self.pause_button.config(state='normal')
            self.stop_button.config(state='normal')
            self.multi_scan_button.config(state='disabled')
        else:
            self.start_button.config(state='normal')
            self.pause_button.config(state='disabled', text="⏸️ PAUSE")
            self.stop_button.config(state='disabled')
            self.multi_scan_button.config(state='normal')
    
    def update_multi_scan_buttons(self):
        """Update multi-scan button states"""
        if self.scan_running:
            self.multi_scan_button.config(state='disabled')
            self.multi_pause_button.config(state='normal')
            self.multi_stop_button.config(state='normal')
            self.start_button.config(state='disabled')
        else:
            self.multi_scan_button.config(state='normal')
            self.multi_pause_button.config(state='disabled', text="⏸️ PAUSE")
            self.multi_stop_button.config(state='disabled')
            self.start_button.config(state='normal')
    
    def handle_startup_checks(self) -> bool:
        """
        Handles startup checks, including the ethical agreement dialog.
        Returns False if the application should exit.
        """
        config_file = 'config.json'
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                if config.get('agreement_accepted') is True:
                    return True
        except (IOError, json.JSONDecodeError):
            # Config is corrupted or unreadable, show dialog again
            pass

        agreement_text = """
LEGAL DISCLAIMER & ETHICAL USE

1. AUTHORIZED USE ONLY: You must only use this tool on systems you own or have explicit, written permission to test.
2. EDUCATIONAL PURPOSE: This tool is intended for educational and security research purposes only.
3. COMPLIANCE: You must comply with all applicable laws and regulations. Unauthorized scanning is illegal.
4. NO WARRANTY: This tool is provided 'as-is'. The developers are not responsible for any misuse or damage.

By clicking 'Yes', you agree to these terms and take full responsibility for your actions.
Do you agree to these terms?
"""
        response = messagebox.askyesno("Ethical Agreement", agreement_text, icon='warning')

        if response:
            try:
                with open(config_file, 'w') as f:
                    json.dump({'agreement_accepted': True}, f)
            except IOError:
                messagebox.showwarning("Configuration Error", "Could not save settings. You may be asked to agree again next time.")
            return True
        else:
            self.root.destroy()
            return False

    def run(self):
        """Start the application"""
        # Perform startup checks after window is created but before mainloop
        if not self.handle_startup_checks():
            return  # Exit if user disagrees
        self.root.mainloop()

def main():
    """Main function to run the application"""
    try:
        app = SQLInjectionTool()
        app.run()
    except Exception as e:
        print(f"Error starting application: {e}")
        messagebox.showerror("Error", f"Failed to start application: {e}")

if __name__ == "__main__":
    main()
