import subprocess


def run_wappalyzer(url: str):
    print(f"\n=== Detectando stack em {url} ===")
    try:
        proc = subprocess.run(
            ["wappalyzer", url],
            capture_output=True, text=True, check=True
        )
        print(proc.stdout)
    except FileNotFoundError:
        print("Erro: wappalyzer CLI não instalado. Rode 'npm install -g wappalyzer'")
    print()
