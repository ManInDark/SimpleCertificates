#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import os
import random
import string
import subprocess

with open('ca/ca.pub', 'r') as file:
    certificate = "\n".join(file.readlines())

# Create a temporary folder in the current directory
tmpdir = os.path.join(os.getcwd(), 'temp')
os.makedirs(tmpdir, exist_ok=True)
for file in os.listdir(tmpdir):
    os.remove(os.path.join(tmpdir, file))

if not os.path.exists('ca/krl'):
    result = subprocess.run('ssh-keygen -kf ca/krl', shell=True)

def send_response(req: BaseHTTPRequestHandler, code: int, message: str):
    req.send_response(code)
    req.send_header('Content-type', 'text/plain')
    req.end_headers()
    req.wfile.write((message + "\n").encode())

def test_write_file(req: BaseHTTPRequestHandler, ext: str, name: str):
    path = os.path.join(tmpdir, name + ext)
    if not os.path.exists(path):
        with open(path, 'wb') as file:
            file.write(req.rfile.read(int(req.headers.get('Content-Length'))))
        send_response(req, 200, name)
        return True
    return False

def write_file(req, extension: str):
    while True:
        r_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(16))
        if test_write_file(req, extension, r_name):
            break

def sslsign(req: BaseHTTPRequestHandler):
    query = parse_qs(urlparse(req.path).query)
    if not 'name' in query:
        send_response(req, 400, 'Bad Request')
        return
    ext_path = os.path.join(tmpdir, query["name"][0] + ".ext")
    csr_path = os.path.join(tmpdir, query["name"][0] + ".csr")
    if not (os.path.exists(csr_path) and os.path.exists(ext_path)):
        send_response(req, 404, 'Not Found')
        return
    result = subprocess.run(f"openssl x509 -req -in {csr_path} -CA ca/ca.pem -CAkey ca/ca.key -out {csr_path.replace('.csr', '.crt')} -days 31 -sha256 -extfile {ext_path} -trustout", shell=True)
    if result.returncode == 0:
        send_response(req, 200, 'success')
    else:
        send_response(req, 500, 'command execution error')

class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/certificateauthority':
            send_response(self, 200, certificate)
            return

        elif self.path.startswith('/sign'):
            query = parse_qs(urlparse(self.path).query)
            if not 'name' in query or not 'identity' in query:
                send_response(self, 400, 'Bad Request')
                return
            certificate_path = os.path.join(tmpdir, query["name"][0] + ".pub")
            if not os.path.exists(certificate_path):
                send_response(self, 404, 'Not Found')
                return
            for char in query["identity"][0]:
                if char not in string.ascii_letters + string.digits + '-_@,.':
                    send_response(self, 400, 'Bad Request')
                    return
            result = subprocess.run(f"ssh-keygen -I '{query['identity'][0]}' -s ca/ca {'-h' if 'server' in query else ''} -n '{query['identity'][0]}' temp/{query['name'][0]}.pub", shell=True)

            if result.returncode == 0:
                send_response(self, 200, 'success')
            else:
                send_response(self, 500, 'command execution error')
            return

        elif self.path.startswith('/sslsign'):
            sslsign(self)
            return
        elif self.path.startswith('/retrieve'):
            query = parse_qs(urlparse(self.path).query)
            if not 'name' in query:
                send_response(self, 400, 'Bad Request')
                return
            certificate_path = os.path.join(tmpdir, query["name"][0] + ".pub")
            certificate_signed_path = os.path.join(tmpdir, query["name"][0] + "-cert.pub")
            if not os.path.exists(certificate_path):
                send_response(self, 404, 'Not Found')
                return
            if not os.path.exists(certificate_signed_path):
                send_response(self, 404, 'Not Signed')
                return
            with open(certificate_signed_path, 'r') as file:
                ret_certificate = "".join(file.readlines())
                send_response(self, 200, ret_certificate)
                os.remove(certificate_path)
                os.remove(certificate_signed_path)
                return

        elif self.path.startswith("/sslretrieve"):
            query = parse_qs(urlparse(self.path).query)
            if not 'name' in query:
                send_response(self, 400, 'Bad Request')
                return
            crt_path = os.path.join(tmpdir, query["name"][0] + ".crt")
            ext_path = os.path.join(tmpdir, query["name"][0] + ".ext")
            csr_path = os.path.join(tmpdir, query["name"][0] + ".csr")
            if not os.path.exists(csr_path):
                send_response(self, 404, 'Not Found')
                return
            elif not (os.path.exists(ext_path) and os.path.exists(crt_path)):
                send_response(self, 400, 'Not Signed')
                return
            with open(crt_path, 'r') as file:
                ret_certificate = "".join(file.readlines())
                send_response(self, 200, ret_certificate)
                os.remove(csr_path)
                os.remove(ext_path)
                os.remove(crt_path)
                return

        elif self.path.startswith("/krl"):
            with open('ca/krl', 'rb') as file:
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.end_headers()
                self.wfile.write(file.read())
                return
        
        elif self.path.startswith("/revoke"):
            query = parse_qs(urlparse(self.path).query)
            if not 'name' in query:
                send_response(self, 400, 'Bad Request')
                return
            certificate_path = os.path.join(tmpdir, query["name"][0] + ".pub")
            if not os.path.exists(certificate_path):
                send_response(self, 404, 'Not Found')
                return
            result = subprocess.run(f"ssh-keygen -kuf ca/krl temp/{query['name'][0]}.pub", shell=True)

            if result.returncode == 0:
                send_response(self, 200, 'success')
            else:
                send_response(self, 500, 'command execution error')
            return

        else:
            send_response(self, 404, 'Not Found')
            return

    # curl -X POST --data @github-key.pub localhost:8000
    def do_POST(self):
        if self.path == '/':
            write_file(self, ".pub")
        elif self.path == '/csr':
            write_file(self, ".csr")
        elif self.path.startswith('/ext'):
            name = self.path.split('/')[-1]
            if name == "ext":
                send_response(self, 400, 'Bad Request')
                return 
            if not os.path.exists(os.path.join(tmpdir, name + ".csr")):
                send_response(self, 404, 'Not Found')
                return
            test_write_file(self, ".ext", name)


if __name__ == '__main__':
    httpd = HTTPServer(('127.0.0.1', 8000), MyHTTPRequestHandler)
    print('Starting server...')
    httpd.serve_forever()
