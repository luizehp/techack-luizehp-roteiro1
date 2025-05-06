# reconapp/subdomain_enum.py

import subprocess
import re

# tenta usar Sublist3r
try:
    import sublist3r
    _USE_SUBLIST3R = True
except ImportError:
    _USE_SUBLIST3R = False

# regex para limpar wildcards
_re_clean = re.compile(r"\*\.")


def enumerate_subdomains(domain: str):

    print(f"\n=== Enumerando subdomínios para {domain} ===")
    encontrados = set()

    # 1) Sublist3r
    if _USE_SUBLIST3R:
        try:
            subs = sublist3r.main(
                domain,         # domínio
                40,             # threads
                None,           # savefile
                None,           # ports
                True,           # silent
                False,          # verbose
                False,          # bruteforce
                None            # engines
            )
            for sub in subs:
                sub = _re_clean.sub("", sub.strip())
                if sub and sub not in encontrados:
                    print(sub)
                    encontrados.add(sub)
            if encontrados:
                return
        except Exception as e:
            print(f"Erro usando Sublist3r: {e}")

    # 2) Amass (fallback)
    try:
        proc = subprocess.run(
            ["amass", "enum", "-d", domain, "-silent"],
            capture_output=True, text=True, check=True
        )
        for line in proc.stdout.splitlines():
            sub = _re_clean.sub("", line.strip())
            if sub and sub not in encontrados:
                print(sub)
                encontrados.add(sub)
        if encontrados:
            return
    except FileNotFoundError:
        # amass não instalado
        pass
    except subprocess.CalledProcessError as e:
        print(f"Erro durante enumeração com Amass: {e}")

    # 3) (Opcional) fallback via crt.sh
    try:
        import requests
        import json
        print("Fallback: consultando crt.sh...")
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=10)
        data = json.loads(resp.text)
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                sub = _re_clean.sub("", name.strip())
                if sub.endswith(domain) and sub not in encontrados:
                    print(sub)
                    encontrados.add(sub)
        if encontrados:
            return
    except Exception as e:
        print(f"Erro no fallback crt.sh: {e}")

    if not encontrados:
        print("Nenhum subdomínio encontrado.")
    print()
