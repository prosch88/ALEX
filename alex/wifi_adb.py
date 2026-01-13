import importlib.metadata
import io
import os
import random
import string
import subprocess
import sys
import time
import _thread
from PIL import Image
import customtkinter as ctk

import qrcode
from zeroconf import IPVersion, ServiceBrowser, ServiceStateChange, Zeroconf

zc = Zeroconf(ip_version=IPVersion.V4Only)
paired = False
connected = False

def get_code(n: int):
    return "".join(random.choices(string.ascii_letters, k=n))

SIZE = 5
NAME = "ADB_WIFI_" + get_code(SIZE)
PASSWORD = get_code(SIZE)
TYPES = ["_adb-tls-connect._tcp.local.", "_adb-tls-pairing._tcp.local."]
ADB_PATH = "adb"
TCPIP_PORT = 5555
device_ports = []
ADDRESS = None

def generate_code(name: str, password: str):
    return f"WIFI:T:ADB;S:{name};P:{password};;"

def make_qr_image(data: str, size: int = 256) -> Image.Image:
    qr = qrcode.QRCode(
        version=None,            
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(
        fill_color="black",
        back_color="white"
    ).convert("RGB")

    return img.resize((size, size), Image.NEAREST)

def pair_device(address: str, port: int, password: str):
    global paired
    #print("in pairing")
    args = [ADB_PATH, "pair", f"{address}:{port}", password]
    out = subprocess.run(args, capture_output=True)
    if out.returncode != 0:
        return
    paired = True
    #print("paired")

def connect_device(address: str, port: int):
    #print("in connecting")
    global connected, paired, exit, ADDRESS
    args = [ADB_PATH, "connect", f"{address}:{port}"]
    out = subprocess.run(args, capture_output=True)
    if out.returncode != 0:
        #print("connect not 0")
        return
    if paired:
        #print("connected")
        connected = True
        if ADDRESS != None:
            ADDRESS = None
            args = [ADB_PATH, "disconnect", f"{address}:{port}"]
            out = subprocess.run(args, capture_output=True)
            #print("disconnected")
            time.sleep(1)
        else:
            zc.close()
            exit.set(1)
        

def on_service_state_change(
    zeroconf: Zeroconf,
    service_type: str,
    name: str,
    state_change: ServiceStateChange,
) -> None:
    
    global PASSWORD

    if state_change is ServiceStateChange.Added:
        info = zeroconf.get_service_info(service_type, name)
        if not info:
            return

        if ADDRESS != None:
            addr = ADDRESS
        else:
            addr = info.parsed_addresses()[0]

        if service_type == "_adb-tls-pairing._tcp.local.":
            if not device_ports:
                return

            pair_port = info.port or 5555
            connect_port = device_ports[0]
            pair_device(addr, pair_port, PASSWORD)
            connect_device(addr, connect_port)
        elif service_type == "_adb-tls-connect._tcp.local.":
            connect_device(addr, TCPIP_PORT)
            device_ports.append(info.port)

 
def wifi_pair(change, imglabel=None, p_addr=None, p_port=None, p_pass=None):
    global exit
    global PASSWORD
    exit = change
    zcopen = True
    if imglabel:
        qrimg =  make_qr_image(generate_code(NAME, PASSWORD))
        qr_ctk_img = ctk.CTkImage(dark_image=qrimg, size=(256, 256))
        imglabel.configure(image=qr_ctk_img)

        ServiceBrowser(
            zc=zc,
            type_=TYPES,
            handlers=[on_service_state_change],
        )
    else:
        if p_addr:
            global device_ports
            global ADDRESS
            PASSWORD = p_pass
            ADDRESS = p_addr
            device_ports.append(p_port)

            ServiceBrowser(
                zc=zc,
                type_=TYPES,
                handlers=[on_service_state_change],
            )
