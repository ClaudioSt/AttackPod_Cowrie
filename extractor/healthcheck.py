# healthcheck.py - reused by docker-compose (simple TCP connect)
import socket, sys
if len(sys.argv) < 3:
    print("usage: healthcheck.py host port")
    sys.exit(2)
host = sys.argv[1]
port = int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect((host, port))
    sys.exit(0)
except Exception as e:
    sys.exit(1)
