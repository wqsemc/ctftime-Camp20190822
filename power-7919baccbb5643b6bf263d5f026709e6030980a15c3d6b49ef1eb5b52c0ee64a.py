import socketserver
import random


# p is prime!
from secrets import flag, p

def px(a):
    return pow(a, a, p)


def go(req):
    while True:
        req.sendall(b"Challenge: ")
        challenge = random.randint(1, p-1)
        req.sendall(bytes(str(challenge), "utf-8"))
        req.sendall(b"\n")

        req.sendall(b"Response: ")
        resp = int(req.recv(4096).strip())
        req.sendall(b"Result: ")
        res = px(resp)
        req.sendall(bytes(str(res), "utf-8"))
        req.sendall(b"\n")

        if px(resp) == challenge:
            req.sendall(flag)
            req.sendall(b"\n")
            req.close()
            return

class incoming(socketserver.BaseRequestHandler):
    def handle(self):
        req = self.request
        go(req)


class ReusableTCPServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


socketserver.TCPServer.allow_reuse_address = True
server = ReusableTCPServer(("0.0.0.0", 1337), incoming)
server.serve_forever()
