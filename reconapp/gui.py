# reconapp/gui.py

import io
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from reconapp.portscan import scan_ports
from reconapp.dns_lookup import lookup_dns_whois
from reconapp.subdomain_enum import enumerate_subdomains
from reconapp.wappalyzer import run_wappalyzer
from reconapp.nikto import run_nikto


class ReconAppGUI(ttk.Frame):
    def __init__(self, root):
        super().__init__(root)
        root.title("ReconApp GUI")
        self.pack(fill="both", expand=True)
        self._build_notebook()

    def _build_notebook(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        tabs = [
            ("PortScan",    self._build_portscan_tab),
            ("DNS/WHOIS",   self._build_dns_tab),
            ("Subdomínios", self._build_subdomain_tab),
            ("Wappalyzer",  self._build_wappalyzer_tab),
            ("Nikto",       self._build_nikto_tab),
        ]
        for title, builder in tabs:
            frame = ttk.Frame(nb)
            nb.add(frame, text=title)
            builder(frame)

    def _build_portscan_tab(self, frame):
        ttk.Label(frame, text="Host/IP:").grid(row=0, column=0, sticky="e")
        host = ttk.Entry(frame)
        host.grid(row=0, column=1, sticky="we")

        ttk.Label(frame, text="Portas (ex: 1-1024):").grid(row=1,
                                                           column=0, sticky="e")
        ports = ttk.Entry(frame)
        ports.grid(row=1, column=1, sticky="we")

        ttk.Label(frame, text="Protocolo:").grid(row=2, column=0, sticky="e")
        proto = ttk.Combobox(frame, values=["TCP", "UDP"], state="readonly")
        proto.current(0)
        proto.grid(row=2, column=1, sticky="we")

        btn = ttk.Button(
            frame, text="Scan",
            command=lambda: self._run_thread(
                scan_ports,
                host.get(), ports.get(), proto.get(),
                callback=self._show_portscan_results
            )
        )
        btn.grid(row=3, column=0, columnspan=2, pady=5)

        self.portout = scrolledtext.ScrolledText(frame, height=10)
        self.portout.grid(row=4, column=0, columnspan=2, sticky="nsew")

        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)

    def _build_dns_tab(self, frame):
        ttk.Label(frame, text="Domínio/IP:").pack(side="left")
        target = ttk.Entry(frame)
        target.pack(side="left", fill="x", expand=True)

        btn = ttk.Button(
            frame, text="Consultar",
            command=lambda: self._run_thread(
                lookup_dns_whois,
                target.get(),
                callback=self._show_dns_results
            )
        )
        btn.pack(side="left", padx=5)

        self.dnsout = scrolledtext.ScrolledText(frame, height=15)
        self.dnsout.pack(fill="both", expand=True)

    def _build_subdomain_tab(self, frame):
        ttk.Label(frame, text="Domínio:").pack(side="left")
        domain = ttk.Entry(frame)
        domain.pack(side="left", fill="x", expand=True)

        btn = ttk.Button(
            frame, text="Enumerar",
            command=lambda: self._run_thread(
                enumerate_subdomains,
                domain.get(),
                callback=self._show_subdomain_results
            )
        )
        btn.pack(side="left", padx=5)

        self.subout = scrolledtext.ScrolledText(frame, height=15)
        self.subout.pack(fill="both", expand=True)

    def _build_wappalyzer_tab(self, frame):
        ttk.Label(frame, text="URL:").pack(side="left")
        url = ttk.Entry(frame)
        url.pack(side="left", fill="x", expand=True)

        btn = ttk.Button(
            frame, text="Detectar",
            command=lambda: self._run_thread(
                run_wappalyzer,
                url.get(),
                callback=self._show_wappalyzer_results
            )
        )
        btn.pack(side="left", padx=5)

        self.webout = scrolledtext.ScrolledText(frame, height=15)
        self.webout.pack(fill="both", expand=True)

    def _build_nikto_tab(self, frame):
        ttk.Label(frame, text="URL:").pack(side="left")
        target = ttk.Entry(frame)
        target.pack(side="left", fill="x", expand=True)

        btn = ttk.Button(
            frame, text="Scan Nikto",
            command=lambda: self._run_thread(
                run_nikto,
                target.get(),
                callback=self._show_nikto_results
            )
        )
        btn.pack(side="left", padx=5)

        self.nikout = scrolledtext.ScrolledText(frame, height=15)
        self.nikout.pack(fill="both", expand=True)

    # Callbacks
    def _show_portscan_results(self, host, ports, proto, results):
        self.portout.delete(1.0, tk.END)
        for port, state, svc in results:
            self.portout.insert(tk.END, f"{port}\t{state}\t{svc}\n")

    def _show_dns_results(self, target, output):
        self.dnsout.delete(1.0, tk.END)
        self.dnsout.insert(tk.END, output or "")

    def _show_subdomain_results(self, domain, output):
        self.subout.delete(1.0, tk.END)
        self.subout.insert(tk.END, output or "")

    def _show_wappalyzer_results(self, url, output):
        self.webout.delete(1.0, tk.END)
        self.webout.insert(tk.END, output or "")

    def _show_nikto_results(self, target, output):
        self.nikout.delete(1.0, tk.END)
        self.nikout.insert(tk.END, output or "")

    # Thread runner with stdout capture
    def _run_thread(self, func, *args, callback=None):
        def task():
            buf = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = buf
            try:
                result = func(*args)
            except Exception as e:
                sys.stdout = old_stdout
                messagebox.showerror("Erro", str(e))
                return
            sys.stdout = old_stdout
            output = buf.getvalue()
            if callback:
                # determine what to pass to callback
                if isinstance(result, list):
                    callback(*args, result)
                else:
                    callback(*args, output)
        threading.Thread(target=task, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    ReconAppGUI(root)
    root.mainloop()
