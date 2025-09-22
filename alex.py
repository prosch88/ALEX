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
from tkinter import StringVar
from importlib.metadata import version
import adbutils
import subprocess
import platform
import shutil
import socket
import time
import re


ctk.set_appearance_mode("dark")  # Dark Mode
ctk.set_default_color_theme(os.path.join(os.path.dirname(__file__), "assets" , "alex_theme.json" ))
ctk.set_window_scaling(1.0)
ctk.set_widget_scaling(1.0) 

class MyApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        #self.stop_event = threading.Event()
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
        #if lockdown != None:
        #    if ispaired != False:
        #        self.show_cwd()
        #    else:
        #        self.show_notpaired()
        #else:
        #    if mode == "normal":
        #        self.show_nodevice()
        #    else:
        #        self.show_recovery()

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
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Reporting Options", command=lambda: self.switch_menu("ReportMenu"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Acquisition Options", command=lambda: self.show_main_menu(), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Logging Options", command=lambda: self.show_main_menu(), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Advanced Options", command=lambda: self.show_main_menu(), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Save informations about the device and installed apps.", 
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
        #elif menu_name == "AcqMenu":
        #    self.show_acq_menu()
        #elif menu_name == "LogMenu":
        #    self.show_log_menu()
        #elif menu_name == "AdvMenu":
        #    self.show_adv_menu()
        #elif menu_name == "PDF":
        #    self.show_pdf_report()
        elif menu_name == "DevInfo":
            self.show_save_device_info()
        #elif menu_name == "Report":
        #    self.show_report()

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
            dir = os.path.join(os.path.expanduser('~'), "ufade_out")
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
    def browse_cwd(self):
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
            ctk.CTkButton(self.dynamic_frame, text="Create PDF Report", command=lambda: self.switch_menu("DevInfo"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Save informations about the device, installed apps,\nSIM and companion devices. (as .txt)",
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



a_version = 0.01
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

def get_client(host=default_host, port=default_port, check=False):
    global adb
    global snr
    global device
    global device_info
    global state
    global paired
    global apps
    try:
        ensure_adb_server()
        adb = adbutils.AdbClient(host=host, port=port)
    except OSError:
        adb = None

    if adb != None:
        try:
            snr = adb.list(extended=True)[0].serial
            state = adb.list(extended=True)[0].state
            device = adb.device(snr)
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
        elif state == "unauthorized ✗":
            dev_state = state
            device_info = ("Device is " + dev_state + "\n\n" +
                    '{:13}'.format("Serialnr: ") + "\t" + snr + "")
        else:
            paired = True
            dev_state = "autorized ✔"

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
            build = getprop(device, "ro.build.display.id")
            global spl
            spl = getprop(device, "ro.build.version.security_patch")
            global locale
            locale = getprop(device, "persist.sys.locale")
            global imei
            imei = getprop(device, 'gsm.baseband.imei').replace("'","")
            if imei == "-":
                imei = getprop(device, 'ro.gsm.imei').replace("'","")
            if imei == "-":
                imei = getprop(device, 'ril.imei').replace("'","")
            if imei == "-":
                imei = device.shell("service call iphonesubinfo 1 s16 com.android.shell | cut -c 52-66 | tr -d '.[:space:]'").replace("'","")
            global b_mac
            b_mac = device.shell("settings get secure bluetooth_address")
            global w_mac
            w_mac = getprop(device, "ro.boot.wifimacaddr")
            if w_mac == "-":
                wifi_dump = device.shell("dumpsys wifi")
                match1 = re.search(r"wifi_sta_factory_mac_address=([0-9a-fA-F:]{17})", wifi_dump)
                match2 = re.search(r" MAC:\s*([0-9a-fA-F:]{17})", wifi_dump)      
                if match1:
                    w_mac = match1.group(1).upper()
                elif match2:
                    w_mac = match2.group(1).upper()
                else:
                    w_mac = "-"
            global d_name
            d_name = device.shell("settings get global device_name")
            if d_name == "":
                d_name = "-"
            else:
                if len(d_name) > 26:
                    wordnames = d_name.split()
                    if len(' '.join(wordnames[:-1])) < 27:
                        name_s = ' '.join(wordnames[:-1]) + "\n" + '{:13}'.format(" ") + "\t" + wordnames[-1]
                    else:
                        name_s = ' '.join(wordnames[:-2]) + "\n" + '{:13}'.format(" ") + "\t" + ' '.join(wordnames[-2:])
                else:
                    name_s = d_name
            global data_s
            global used
            global free
            data_df = device.shell("df -h /data")
            if "invalid option" in data_df.lower():
                data_df = device.shell("df /data")
            data_lines = data_df.strip().splitlines()
            if len(data_lines) >= 2:
                data_line = data_lines[1]
                parts = re.split(r"\s+", data_line)
                size, used, avail, use_percent = parts[1:5]
                data_s = f"{add_space(size)}B"
                used = f"{add_space(used)}B"
                free = f"{add_space(avail)}B"
                try: graph_progress = "" + "▓" * int(26/100*int(use_percent.rstrip("%"))) + "░" * int(26/100*(100-int(use_percent.rstrip("%")))) + ""
                except: graph_progress = "-"
            else:
                data_s, used, free, use_percent = "-"
                graph_progress = "-"
            global ad_id
            ad_id = device.shell("settings get secure android_id")
            if ad_id == "":
                ad_id = "-"

            global apps
            app_query = name = device.shell("pm list packages -3 -i")
            pattern = re.compile(r"package:([^\s]+)\s+installer=([^\s]+)")
            apps = [[pkg, installer] for pkg, installer in pattern.findall(app_query)]



            device_info = ("Device is " + dev_state + "\n\n" +
                    '{:13}'.format("Model: ") + "\t" + full_name +
                    "\n" + '{:13}'.format("Name: ") + "\t" + name_s +
                    "\n" + '{:13}'.format("Product: ") + "\t" + product +
                    "\n" + '{:13}'.format("Platform: ") + "\t" + d_platform +
                    "\n" + '{:13}'.format("Software: ") + "\t" + software +
                    "\n" + '{:13}'.format("Build-Nr: ") + "\t" + build +
                    "\n" + '{:13}'.format("SPL: ") + "\t" + spl +
                    "\n" + '{:13}'.format("Language: ") + "\t" + locale +
                    "\n" + '{:13}'.format("Serialnr: ") + "\t" + snr +
                    "\n" + '{:13}'.format("IMEI: ") + "\t" + imei +
                    "\n" + '{:13}'.format("Wifi MAC: ") + "\t" + w_mac +
                    "\n" + '{:13}'.format("BT MAC: ") + "\t" + b_mac +
                    "\n" + '{:13}'.format("Disk Use: ") + "\t" + graph_progress +
                    "\n" + '{:13}'.format("Data: ") + "\t" + data_s +
                    "\n" + '{:13}'.format("Used: ") + "\t" + used +
                    "\n" + '{:13}'.format("Free: ") + "\t" + free +
                    "\n" + '{:13}'.format("Ad-ID: ") + "\t" + ad_id)             

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

def save_info():
    file = open("device_" + snr + ".txt", "w", encoding='utf-8')
    file.write("## DEVICE ##\n\n" + "Model-Nr:   " + full_name + "\nDev-Name:   " + d_name + "\nProduct:    " + product + 
        "\nPlatform:   " + d_platform + "\nSoftware:   " + software + "\nBuild-Nr:   " + build + "\nLanguage:   " + locale + "\nSerialnr:   " + snr + 
        "\nWifi MAC:   " + w_mac + "\nBT-MAC:     " + b_mac + "\nData:       " + data_s + "\nFree Space: " + free + 
        "\nAD-ID :     " + ad_id + "\nIMEI :      " + imei)    
    
    #Save user-installed Apps to txt
    try: al = str(len(max([app[0] for app in apps], key=len)))  
    except: al = 40 
    file.write("\n\n" + "## Installed Apps (by user) ## \n\n")
    if len(apps) > 0:
        file.write('{:{l}}'.format("app", l=al) + "\t" + "installer\n")
    else:
        file.write('None')
   
    for app in apps:
        file.write("\n" + '{:{l}}'.format(app[0], l=al) + "\t" + app[1])
            
    file.close()


device = None
paired = False
apps = []
adb = None
state = None
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