import subprocess


def run_nikto(url: str):
    print(f"\n=== Executando Nikto contra {url} ===")
    try:
        subprocess.run(["nikto", "-h", url, "-o",
                       "nikto_report.html"], check=True)
        print("Relatório salvo em nikto_report.html")
    except FileNotFoundError:
        print("Erro: nikto não encontrado. Instale via 'apt install nikto' ou similar.")
    except subprocess.CalledProcessError as e:
        print(f"Erro Nikto: {e}")
    print()
