import socket
import threading
import errno
from typing import List, Tuple


def scan_tcp_port(host: str, port: int, results: List[Tuple[int, str, str]]):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    code = s.connect_ex((host, port))
    if code == 0:
        state = "Open"
    elif code == errno.ECONNREFUSED:
        state = "Closed"
    elif code == errno.ETIMEDOUT:
        state = "Filtered"
    else:
        state = f"Unknown ({code})"
    try:
        service = socket.getservbyport(
            port, 'tcp') if state == "Open" else "N/A"
    except Exception:
        service = "Unknown"
    s.close()
    if state == "Open":
        results.append((port, state, service))


def scan_udp_port(host: str, port: int, results: List[Tuple[int, str, str]]):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    s.sendto(b"", (host, port))
    try:
        s.recvfrom(1024)
        state = "Open"
    except socket.timeout:
        state = "Open|Filtered"
    try:
        service = socket.getservbyport(
            port, 'udp') if state == "Open" else "N/A"
    except Exception:
        service = "Unknown"
    s.close()
    if state.startswith("Open"):
        results.append((port, state, service))


def scan_ports(host: str, start_port: int, end_port: int, protocol: str) -> List[Tuple[int, str, str]]:
    results: List[Tuple[int, str, str]] = []
    threads = []
    for port in range(start_port, end_port + 1):
        if protocol == "TCP":
            t = threading.Thread(target=scan_tcp_port,
                                 args=(host, port, results))
        else:
            t = threading.Thread(target=scan_udp_port,
                                 args=(host, port, results))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    return sorted(results, key=lambda x: x[0])
