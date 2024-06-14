from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import os
import random
import string
import subprocess

with open('ca/ca.pub', 'rb') as file:
    certificate = file.read()

# Create a temporary folder in the current directory
tmpdir = os.path.join(os.getcwd(), 'temp')
os.makedirs(tmpdir, exist_ok=True)
for file in os.listdir(tmpdir):
    os.remove(os.path.join(tmpdir, file))

class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/certificateauthority':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(certificate)
            return
        elif self.path.startswith('/sign'):
            query = parse_qs(urlparse(self.path).query)
            if not 'name' in query or not 'identity' in query:
                self.send_response(400)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Bad Request\n')
                return
            certificate_path = os.path.join(tmpdir, query["name"][0] + ".pub")
            print(certificate_path)
            if not os.path.exists(certificate_path):
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Not Found\n')
                return
            for char in query["identity"][0]:
                if char not in string.ascii_letters + string.digits + '-_@,.':
                    self.send_response(400)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b'Bad Request\n')
                    return
            result = subprocess.run(f"ssh-keygen -I 'host key' -s ca/ca {'-h' if 'server' in query else ''} -n '{query['identity'][0]}' temp/{query['name'][0]}.pub", shell=True)

            if result.returncode == 0:
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'success\n')
            else:
                self.send_response(500)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'command execution error\n')
            return
        elif self.path.startswith('/retrieve'):
            query = parse_qs(urlparse(self.path).query)
            if not 'name' in query:
                self.send_response(400)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Bad Request\n')
                return
            certificate_path = os.path.join(tmpdir, query["name"][0] + ".pub")
            certificate_signed_path = os.path.join(tmpdir, query["name"][0] + "-cert.pub")
            if not os.path.exists(certificate_path):
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Not Found\n')
                return
            if not os.path.exists(certificate_signed_path):
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Not Signed\n')
                return
            with open(certificate_signed_path, 'rb') as file:
                ret_certificate = file.read()
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(ret_certificate)
                os.remove(certificate_path)
                os.remove(certificate_signed_path)
                return
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found\n')
            return

    # curl -X POST --data @github-key.pub localhost:8000
    def do_POST(self):
        while True:
            r_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(16))
            certificate_path = os.path.join(tmpdir, r_name + ".pub")
            if not os.path.exists(certificate_path):
                with open(certificate_path, 'wb') as file:
                    file.write(self.rfile.read(int(self.headers.get('Content-Length'))))
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write((r_name + "\n").encode())
                break

if __name__ == '__main__':
    httpd = HTTPServer(('127.0.0.1', 8000), MyHTTPRequestHandler)
    print('Starting server...')
    httpd.serve_forever()

# ssh-keygen -I "host key" -s ca/ca -h temp/key.pub