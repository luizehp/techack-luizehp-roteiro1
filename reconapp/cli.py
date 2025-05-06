import sys
from reconapp.portscan import scan_ports
from reconapp.dns_lookup import lookup_dns_whois
from reconapp.subdomain_enum import enumerate_subdomains
from reconapp.wappalyzer import analyze_stack
from reconapp.nikto import run_nikto


def menu():
    print("Bem-vindo ao ReconApp!")
    print("1. PortScan")
    print("2. DNS Lookup / WHOIS")
    print("3. Enumeração de Subdomínios")
    print("4. Wappalyzer (detecção de stack)")
    print("5. Scanner de vulnerabilidades (Nikto)")
    print("6. Sair")
    return input("Escolha uma opção: ").strip()


def main():
    while True:
        choice = menu()
        if choice == '1':
            host = input("Host ou IP: ").strip()
            rng = input("Intervalo de portas (ex: 1-1024): ").strip()
            proto = input("Protocolo (TCP/UDP): ").strip().upper()
            start, end = map(int, rng.split('-'))
            results = scan_ports(host, start, end, proto)
            print("\nPorta\tEstado\tServiço")
            for port, state, svc in results:
                print(f"{port}\t{state}\t{svc}")
            print()
        elif choice == '2':
            target = input("Domínio ou IP: ").strip()
            lookup_dns_whois(target)
        elif choice == '3':
            domain = input("Domínio: ").strip()
            enumerate_subdomains(domain)
        elif choice == '4':
            url = input("URL (ex: https://exemplo.com): ").strip()
            analyze_stack(url)
        elif choice == '5':
            url = input("URL para Nikto (ex: http://exemplo.com): ").strip()
            run_nikto(url)
        elif choice == '6':
            print("Saindo...")
            sys.exit(0)
        else:
            print("Opção inválida! Tente novamente.\n")


if __name__ == '__main__':
    main()
