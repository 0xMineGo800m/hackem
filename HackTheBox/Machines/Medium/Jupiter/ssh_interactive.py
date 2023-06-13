#!/usr/bin/python3

import paramiko
from Crypto.PublicKey import RSA
from pwn import log

def connect(hostname:str = "jupiter.htb", port:int = 22, username:str = "root", pkey:paramiko.PKey = ""):

    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        client.connect(hostname=hostname, port=port, username=username, pkey=pkey)

        while True:
            try:
                cmd = input("$> ")
                if cmd == "exit": break
                stdin, stdout, stderr = client.exec_command(cmd)
                log.info(stdout.read().decode())
                # print(stdout.read().decode()))
            except KeyboardInterrupt:
                break
            
        client.close()
    except Exception as e:
        log.failure(f"General error [{str(e)}]")
