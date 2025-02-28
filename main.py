import socket
import threading
import errno
import tkinter as tk
from tkinter import messagebox, scrolledtext

def scan_tcp_port(host, port, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        code = s.connect_ex((host, port))
        a=0
        if code == 0:
            state = "Open"
        elif code == errno.ECONNREFUSED:
            state = "Closed"
        elif code == errno.ETIMEDOUT:
            state = "Filtered (Timeout)"
        else:
            a=1
            state = f"Unknown ({code})"
        
        if state == "Open":
            try:
                service = socket.getservbyport(port, 'tcp')
            except Exception:
                service = "Unknown"
        else:
            service = "N/A"
        s.close()
        if a==0:
            results.append((port, state, service))
        a=0
    except Exception:
        pass

def scan_udp_port(host, port, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b"", (host, port))
        a=0
        try:
            data, addr = s.recvfrom(1024)
            state = "Open"
        except socket.timeout:
            state = "Open|Filtered"
        
        if state == "Open":
            try:
                service = socket.getservbyport(port, 'udp')
            except Exception:
                service = "Unknown"
        else:
            a=1
            service = "N/A"
        s.close()
        if a==0:
            results.append((port, state, service))
        a=0
    except Exception:
        pass

def start_scan():
    host = host_entry.get().strip()
    port_range = port_entry.get().strip()
    protocol = protocol_var.get()

    try:
        start_port, end_port = map(int, port_range.split('-'))
        if start_port < 0 or end_port < start_port:
            raise ValueError
    except Exception:
        messagebox.showerror("Erro", "Insira um intervalo válido de portas (ex: 1-1000)")
        return

    results = []
    threads = []
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Iniciando escaneamento em {host} (Protocolo: {protocol}) para portas de {start_port} até {end_port}...\n\n")

    for port in range(start_port, end_port + 1):
        if protocol == "TCP":
            t = threading.Thread(target=scan_tcp_port, args=(host, port, results))
        else: 
            t = threading.Thread(target=scan_udp_port, args=(host, port, results))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if results:
        results.sort(key=lambda x: x[0])
        for port, state, service in results:
            output_text.insert(tk.END, f"Porta {port} - Estado: {state} - Serviço: {service}\n")
    else:
        output_text.insert(tk.END, "Nenhuma porta com conexão foi encontrada.")

root = tk.Tk()
root.title("Port Scanner")

tk.Label(root, text="Host:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
host_entry = tk.Entry(root, width=30)
host_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(root, text="Intervalo de Portas (ex: 20-1024):").grid(row=1, column=0, padx=5, pady=5, sticky="e")
port_entry = tk.Entry(root, width=30)
port_entry.grid(row=1, column=1, padx=5, pady=5)

protocol_var = tk.StringVar(value="TCP")
tk.Label(root, text="Protocolo:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
tcp_radio = tk.Radiobutton(root, text="TCP", variable=protocol_var, value="TCP")
tcp_radio.grid(row=2, column=1, sticky="w", padx=5)
udp_radio = tk.Radiobutton(root, text="UDP", variable=protocol_var, value="UDP")
udp_radio.grid(row=2, column=1, sticky="e", padx=5)

scan_button = tk.Button(root, text="Iniciar Escaneamento", command=start_scan)
scan_button.grid(row=3, column=0, columnspan=2, pady=10)

output_text = scrolledtext.ScrolledText(root, width=60, height=15)
output_text.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

root.mainloop()
