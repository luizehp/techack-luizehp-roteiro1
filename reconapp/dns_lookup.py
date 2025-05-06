import subprocess
import whois
import dns.resolver


def lookup_dns_whois(target: str):
    print(f"\n=== WHOIS for {target} ===")
    try:
        w = whois.whois(target)
        for k, v in w.items():
            print(f"{k}: {v}")
    except Exception as e:
        print(f"Erro WHOIS: {e}")

    print(f"\n=== DNS records for {target} ===")
    records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    for rtype in records:
        try:
            answers = dns.resolver.resolve(target, rtype)
            for ans in answers:
                print(f"{rtype}: {ans}")
        except Exception:
            pass
    print()
