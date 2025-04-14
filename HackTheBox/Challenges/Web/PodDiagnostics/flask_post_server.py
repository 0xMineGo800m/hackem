# save as server.py
from flask import Flask, request

app = Flask(__name__)

@app.route("/", methods=["POST"])
def receive():
    data = request.get_data()
    with open("output.raw", "wb") as f:
        f.write(data)
    print("[+] Received POST and saved to output.raw!")
    return "ok"

app.run(host="0.0.0.0", port=7001)
