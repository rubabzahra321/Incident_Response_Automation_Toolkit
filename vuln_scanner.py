
import socket
import pandas as pd

def scan_host(host, ports=[22,80,443,3306,8080]):
    results = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        try:
            s.connect((host, p))
            try:
                s.send(b"HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n".replace(b"{}", host.encode()))
            except Exception:
                pass
            results.append({"port": p, "status": "open"})
            s.close()
        except Exception:
            results.append({"port": p, "status": "closed"})
    return pd.DataFrame(results)
