#!/usr/bin/env python3
import http.server
import json
import os
import ssl


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"service": os.environ.get("SERVICE_NAME", "tls-lab"), "lab_only": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
cert_dir = "/certs/" + os.environ.get("SERVICE_NAME", "valid")
context.load_cert_chain(cert_dir + "/cert.pem", cert_dir + "/key.pem")
server = http.server.ThreadingHTTPServer(("0.0.0.0", 443), Handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
