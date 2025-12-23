import re
import xml.etree.ElementTree as ET
from xml.dom import minidom
import json
import secrets
import hashlib
import html
from datetime import datetime, timezone

def add_separator_centered(parent, title: str, width: int = 30):
    parent.append(ET.Comment("=" * width))
    centered = f"{title:^{width}}"  
    parent.append(ET.Comment(centered))
    parent.append(ET.Comment("=" * width))

def seconds_to_hms(seconds: int) -> str:
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours}:{minutes:02d}:{secs:02d}"

def random_sha256():
    rando = secrets.token_bytes(32)
    sha256_hash = hashlib.sha256()
    sha256_hash.update(rando)
    random256 = sha256_hash.hexdigest()
    return random256

def ufd_report_xml(contact_dict, call_dict, calendar_dict, sms_dict, mms_dict, mms_part_dict, mms_addr_dict, brand="Unknown", model="Unknown", sw= "", revision="-", imei="-", adid="-", estarttime="", endtime="", aversion="0", zipname=""):
    contacts = {}
    for entry in contact_dict:
        cid = entry.get("contact_id")
        if not cid:
            continue
        name = entry.get("display_name") or "Unknown"
        account = entry.get("account_name") or "Unknown"

        numbers = []
        for i in range(1, 16):
            val = entry.get(f"data{i}")
            if not val:
                continue

            val = val.strip().replace(" ", "")
            if not re.match(r'^[+0]', val):
                continue

            match = re.findall(r'^[+0-9]+$', val)
            if match and len(val) > 3:
                numbers.append(val)

        if not numbers:
            continue

        if cid not in contacts:
            contacts[cid] = {
                "name": name.strip(),
                "account": account.strip(),
                "numbers": set()
            }
        contacts[cid]["numbers"].update(numbers)

    root = ET.Element("reports")
    report_el = ET.SubElement(root, "report")

    #Phone Book
    add_separator_centered(report_el, "Phone Book")
    contacts_el = ET.SubElement(report_el, "contacts")
    contact_sha = random_sha256()
    ET.SubElement(contacts_el, "sha256").text = contact_sha
    con_count = ET.SubElement(contacts_el, "count")
    i = 0
    contact_map = {}
    for new_id, cid in enumerate(sorted(contacts.keys(), key=lambda x: int(x)), start=1):
        cdata = contacts[cid]
        contact_el = ET.SubElement(contacts_el, "contact")
        ET.SubElement(contact_el, "id").text = str(new_id)
        ET.SubElement(contact_el, "name").text = cdata["name"]
        ET.SubElement(contact_el, "memory").text = "Phone"
        i += 1

        for number in sorted(cdata["numbers"]):
            phone_el = ET.SubElement(contact_el, "phone_number")
            ET.SubElement(phone_el, "designation").text = "Mobile"
            ET.SubElement(phone_el, "value").text = number
            normalized = number.replace("-", "")
            contact_map[normalized] = f"{cdata['name']} "
        
    # Callog
    incoming = []
    outgoing = []
    missed = []
    unknown = []

    con_count.text = str(i)

    for entry in call_dict:
        c_id = entry.get("_id")
        if c_id is None:
            continue

        di_type = entry.get("type")
        if not di_type:
            continue

        if di_type in ["1", "3"]:
            c_type = "Incoming"
        elif di_type in ["2", "5"]:
            c_type = "Outgoing"
        else:
            c_type = "Unknown"

        c_name = entry.get("name") or "Unknown"
        c_number = entry.get("normalized_number") or "Unknown"

        c_time = entry.get("date")
        if c_time:
            starttime = datetime.fromtimestamp(int(c_time) / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        else:
            starttime = ""

        c_dur = entry.get("duration")
        try:
            dur_sec = int(c_dur)
        except (TypeError, ValueError):
            dur_sec = 0

        duration_str = seconds_to_hms(dur_sec) if dur_sec > 0 else ("N/A" if c_type == "Outgoing" else "0:00:00")

        if c_type == "Incoming" and dur_sec > 0:
            incoming.append((int(c_id), c_type, c_number, c_name, starttime, duration_str))
        elif c_type == "Incoming" and dur_sec == 0:
            missed.append((int(c_id), "Missed", c_number, c_name, starttime, ""))
        elif c_type == "Outgoing":
            outgoing.append((int(c_id), c_type, c_number, c_name, starttime, duration_str))
        else:
            unknown.append((int(c_id), c_type, c_number, c_name, starttime, duration_str))

    # Sorting in reverse (Like CB does it)
    incoming.sort(key=lambda x: x[0], reverse=True)
    outgoing.sort(key=lambda x: x[0], reverse=True)
    missed.sort(key=lambda x: x[0], reverse=True)
    unknown.sort(key=lambda x: x[0], reverse=True)


    # Helper for Calls
    def add_call_section(parent, section_name, tag_name, value_list):
        section_el = ET.SubElement(parent, section_name)
        section_sha = random_sha256()
        ET.SubElement(section_el, "sha256").text = section_sha
        if not value_list:
            section_el.text = ""
            return

        for new_id, (_, c_type, c_number, c_name, starttime, duration) in enumerate(value_list, start=1):
            call_el = ET.SubElement(section_el, tag_name)
            ET.SubElement(call_el, "id").text = str(new_id)
            ET.SubElement(call_el, "type").text = c_type
            ET.SubElement(call_el, "number").text = c_number
            ET.SubElement(call_el, "name").text = c_name
            ET.SubElement(call_el, "timestamp").text = starttime
            if duration != "":
                ET.SubElement(call_el, "duration").text = duration

    # Add Calls to XML
    add_separator_centered(report_el, "Call logs (incoming)")
    add_call_section(report_el, "incoming_calls", "incoming_call", incoming)
    add_separator_centered(report_el, "Call logs (outgoing)")
    add_call_section(report_el, "outgoing_calls", "outgoing_call", outgoing)
    add_separator_centered(report_el, "Call logs (missed)")
    add_call_section(report_el, "missed_calls", "missed_call", missed)
    add_separator_centered(report_el, "Call logs (unknown)")
    add_call_section(report_el, "unknown_calls", "unknown_call", unknown)

    """
    #Locations
    add_separator_centered(report_el, "Location")
    location_el = ET.SubElement(report_el, "locations")
    ET.SubElement(location_el, "entry").text = ""
    """

    #Calendar
    add_separator_centered(report_el, "Calendar")
    calendar_el = ET.SubElement(report_el, "calendar")
    for entry in calendar_dict:
        cal_id = entry.get("_id")
        if cal_id is None:
            continue
        cal_sub = entry.get("title")
        cal_loc = entry.get("eventLocation")
        cal_des = entry.get("description")
        cs_time = entry.get("dtstart")
        ce_time = entry.get("dtend")
        if cs_time:
            cal_start = datetime.fromtimestamp(int(cs_time) / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        else:
            cal_start = ""
        if ce_time:
            cal_end = datetime.fromtimestamp(int(ce_time) / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        else:
            cal_end = ""
        cal_alarm = entry.get("hasAlarm")
        if cal_alarm == 1:
            al_time = datetime.fromtimestamp((int(cs_time) / 1000) - 60, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        else:
            al_time = ""

        calendar_entry = ET.SubElement(calendar_el, "entry")
        ET.SubElement(calendar_entry, "id").text = str(cal_id)
        ET.SubElement(calendar_entry, "subject").text = cal_sub
        ET.SubElement(calendar_entry, "location").text = cal_loc
        ET.SubElement(calendar_entry, "description").text = cal_des
        ET.SubElement(calendar_entry, "start").text = cal_start
        ET.SubElement(calendar_entry, "end").text = cal_end
        ET.SubElement(calendar_entry, "alarm_time").text = al_time
        ET.SubElement(calendar_entry, "repeat_until").text = ""
        ET.SubElement(calendar_entry, "repeat_type").text = ""
        ET.SubElement(calendar_entry, "repeat_position").text = ""
        ET.SubElement(calendar_entry, "repeat_every").text = ""

    #Tasks
    add_separator_centered(report_el, "Tasks")
    tasks_el = ET.SubElement(report_el, "tasks").text = ""
    
    #Notes
    add_separator_centered(report_el, "Notes")
    notes_el = ET.SubElement(report_el, "notes").text = ""

    #SMS
    add_separator_centered(report_el, "SMS Messages")
    sms_el = ET.SubElement(report_el, "sms_messages")
    sms_sha = random_sha256()
    ET.SubElement(sms_el, "sha256").text = sms_sha

    def get_sms_timestamp(s):
        ts = s.get("date_sent") if s.get("type") == "2" and s.get("date_sent") and s.get("date_sent") != "0" else s.get("date")
        try:
            return int(ts)
        except (TypeError, ValueError):
            return 0

    sorted_sms = sorted(
        [s for s in sms_dict if s.get("type") in ("1", "2")],
        key=get_sms_timestamp
    )
    for new_id, sms in enumerate(sorted_sms, start=1):
        sms_entry = ET.SubElement(sms_el, "sms_message")
        ET.SubElement(sms_entry, "id").text = str(new_id)

        address = sms.get("address", "")
        name_value = "N/A"
        number_value = ""

        #Address or Number
        if re.match(r"^[+0-9]+$", address.strip()):
            number_value = address.strip()
            #Try to find a contact to the number
            for stored_num, contact_name in contact_map.items():
                if stored_num.endswith(number_value[-7:]):  # letzte Ziffern vergleichen
                    name_value = contact_name
                    break
        elif address:
            name_value = address.strip()

        ET.SubElement(sms_entry, "number").text = number_value
        ET.SubElement(sms_entry, "name").text = name_value
        
        ts_key = "date_sent" if sms.get("type") == "2" and sms.get("date_sent") and sms.get("date_sent") != "0" else "date"
        timestamp = sms.get(ts_key)
        if timestamp:
            dt = datetime.fromtimestamp(int(timestamp) / 1000 , tz=timezone.utc)
            ET.SubElement(sms_entry, "timestamp").text = dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
        else:
            ET.SubElement(sms_entry, "timestamp").text = ""

        sms_type = sms.get("type")
        status_val = sms.get("status", "0")
        read_val = sms.get("read", "0")
        if sms_type == "1":  # Incoming
            status = "Read" if read_val == "1" else "Unread"
            folder = "Inbox"
            msg_type = "Incoming"
        elif sms_type == "2":  # Outgoing
            folder = "Sent"
            if sms.get("date_sent") and sms.get("date_sent") != "0":
                status = "Sent"
            else:
                status = "Unsent"
            msg_type = "Outgoing"
        else:
            continue

        ET.SubElement(sms_entry, "status").text = status
        ET.SubElement(sms_entry, "folder").text = folder
        ET.SubElement(sms_entry, "storage").text = "Phone"
        ET.SubElement(sms_entry, "type").text = msg_type
        text_value = sms.get("body") or ""
        ET.SubElement(sms_entry, "text").text = html.escape(text_value)
        ET.SubElement(sms_entry, "smsc").text = sms.get("service_center", "") or ""

    
    #MMS
    add_separator_centered(report_el, "MMS Messages")
    mms_el = ET.SubElement(report_el, "mms_messages")
    mms_sha = random_sha256()
    ET.SubElement(mms_el, "sha256").text = mms_sha

    try:
        mms_messages = []
        mms_map = {m["_id"]: m for m in mms_dict}

        addr_map = {}
        for a in mms_addr_dict:
            msg_id = a.get("msg_id")
            if msg_id:
                addr_map.setdefault(msg_id, []).append(a)

        for part in mms_part_dict:
            if part.get("ct") != "text/plain":
                continue

            msg_id = part.get("mid")
            if not msg_id or msg_id not in mms_map:
                continue

            mms = mms_map[msg_id]

            # Folder & Type
            msg_box = mms.get("msg_box")
            if msg_box == "1":
                folder = "Inbox"
                msg_type = "Incoming"
                timestamp_raw = mms.get("date")
            elif msg_box == "2":
                folder = "Sent"
                msg_type = "Outgoing"
                timestamp_raw = mms.get("date")
            else:
                continue

            # Timestamp
            try:
                dt = datetime.fromtimestamp(
                    int(timestamp_raw),
                    tz=timezone.utc
                )
                timestamp = dt.strftime("%Y-%m-%dT%H:%M:%S+02:00")
            except (TypeError, ValueError):
                timestamp = ""

            # Status
            if msg_type == "Incoming":
                status = "Read" if mms.get("read") == "1" else "Unread"
                if status == "Unread":
                    timestamp = ""
            else:
                if "1970" in timestamp:
                    status = "Unsent"
                    timestamp = ""
                else:
                    status = "Sent"

            # From / To
            number_value = ""
            name_value = "N/A"

            for addr in addr_map.get(msg_id, []):
                addr_type = addr.get("type")
                address = (addr.get("address") or "").strip()

                if addr_type == "137":  # From
                    if re.match(r"^[+0-9]+$", address):
                        from_number = address
                        from_name = "N/A"
                    elif address:
                        from_name = address
                        from_number = ""

                elif addr_type == "151":  # To
                    if re.match(r"^[+0-9]+$", address):
                        to_number = address
                        to_name = "N/A"
                    elif address:
                        to_name = address
                        to_number = ""

            text = html.escape(part.get("text") or "")
            mms_entry = ET.SubElement(mms_el, "mms_message")
            ET.SubElement(mms_entry, "id").text = msg_id
            ET.SubElement(mms_entry, "timestamp").text = timestamp
            ET.SubElement(mms_entry, "folder").text = folder
            ET.SubElement(mms_entry, "status").text = status
            ET.SubElement(mms_entry, "priority").text = "Unknown"
            mms_from_entry = ET.SubElement(mms_entry, "from")
            if from_number != "":
                ET.SubElement(mms_from_entry, "number").text = from_number
            elif "@" in from_name:
                ET.SubElement(mms_from_entry, "email").text = from_name
            else:
                ET.SubElement(mms_from_entry, "name").text = from_name
            mms_to_entry = ET.SubElement(mms_entry, "to")
            if to_number != "":
                ET.SubElement(mms_to_entry, "number").text = to_number
            elif "@" in from_name:
                ET.SubElement(mms_to_entry, "email").text = to_name
            else:
                ET.SubElement(mms_to_entry, "name").text = to_name
            mms_body_entry = ET.SubElement(mms_entry, "body")
            ET.SubElement(mms_body_entry, "preview").text = text

    except:
        pass
        #mms_el = ET.SubElement(report_el, "mms_message").text = ""
        

    """
    #Images
    add_separator_centered(report_el, "Images")
    images_el = ET.SubElement(report_el, "image_files").text = ""


    #Ringtones
    add_separator_centered(report_el, "Ringtones")
    ring_el = ET.SubElement(report_el, "ringtone_files").text = ""


    #Audio
    add_separator_centered(report_el, "Audio")
    audio_el = ET.SubElement(report_el, "audio_files").text = ""

    #Video
    add_separator_centered(report_el, "Video")
    video_el = ET.SubElement(report_el, "video_files").text = ""

    #Documents
    add_separator_centered(report_el, "Documents")
    document_el = ET.SubElement(report_el, "documents_files").text = ""

    #Archives
    add_separator_centered(report_el, "Archives")
    archive_el = ET.SubElement(report_el, "archives_files").text = ""
    """

    #Databases
    add_separator_centered(report_el, "Databases")
    database_el = ET.SubElement(report_el, "databases_files")
    container_el = ET.SubElement(database_el, "container")
    ET.SubElement(container_el, "id").text = "1"
    ET.SubElement(container_el, "container_name").text = zipname
    ET.SubElement(container_el, "data_size").text = ""

    #General
    add_separator_centered(report_el, "General information")
    general_el = ET.SubElement(report_el, "general_information")
    ET.SubElement(general_el, "report_type").text = "cell"
    ET.SubElement(general_el, "selected_manufacture").text = "Detected Model"
    ET.SubElement(general_el, "selected_model").text = model
    ET.SubElement(general_el, "detected_manufacture").text = brand
    ET.SubElement(general_el, "detected_model").text = model
    ET.SubElement(general_el, "revision").text = f"{sw} {revision}"
    ET.SubElement(general_el, "imei").text = imei
    ET.SubElement(general_el, "advertisingid").text = adid
    ET.SubElement(general_el, "start_date_time").text = estarttime
    ET.SubElement(general_el, "end_date_time").text = endtime
    ET.SubElement(general_el, "phone_date_time").text = estarttime
    ET.SubElement(general_el, "connection_type").text = "USB Cable"
    ufed_ver_el = ET.SubElement(general_el, "ufed_version")
    ET.SubElement(ufed_ver_el, "xml_format").text = "1.0.2.9"
    ET.SubElement(ufed_ver_el, "software").text = f"{aversion} ALEX"
    ET.SubElement(ufed_ver_el, "serial").text = "ALEX is free and open source"
    ET.SubElement(general_el, "usingclient").text = "0"

#Selection
    add_separator_centered(report_el, "Selection")
    selection_el = ET.SubElement(report_el, "selection_information")
    ET.SubElement(selection_el, "contacts").text = "Selected"
    ET.SubElement(selection_el, "sms").text = "Selected"
    ET.SubElement(selection_el, "call_logs").text = "Selected"
    ET.SubElement(selection_el, "mms").text = "Selected"
    ET.SubElement(selection_el, "email").text = "Not Supported"
    ET.SubElement(selection_el, "im_messages").text = "Not Supported"
    ET.SubElement(selection_el, "calendar").text = "Selected"
    ET.SubElement(selection_el, "tasks").text = "Selected"
    ET.SubElement(selection_el, "notes").text = "Selected"
    ET.SubElement(selection_el, "databases").text = "Selected"
    ET.SubElement(selection_el, "user_dictionary").text = "Not Supported"

#Extraction Notes
    add_separator_centered(report_el, "Extraction Notes")
    selection_el = ET.SubElement(report_el, "extraction_notes").text = ""


    # XML formatting
    ET.indent(root, space="    ")
    xml_str = ET.tostring(root, encoding="utf-8").decode("utf-8")
    xml_output = f"<?xml version='1.0' encoding='utf-8' standalone='yes'?>\n{xml_str}"

    return xml_output



    