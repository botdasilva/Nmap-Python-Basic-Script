import nmap
import sys

# Criar uma instância do scanner nmap
try:
    scanner = nmap.PortScanner()
except nmap.PortScannerError:
    print("Nmap não encontrado. Certifique-se de que está instalado no seu sistema.")
    sys.exit(1)

# Perform a TCP connect scan on a target host
target = input("Digite o seu alvo (ex: 127.0.0.1 ou scanme.nmap.org): ")

print(f"\nEscaneando {target} com um TCP Connect Scan (-sT)...")

# O scan -sT pode exigir privilégios de administrador dependendo do OS/Firewall
# Tente rodar com 'sudo python seu_script.py' se não funcionar
try:
    scanner.scan(target, arguments="-sT")
except Exception as e:
    print(f"Erro durante o scan: {e}")
    sys.exit(1)


# Imprimir portas abertas e serviços associados
for host in scanner.all_hosts():
    # Verifica se o host está online antes de processar
    if scanner[host].state() == 'up':
        print("-" * 40)
        print(f"Host: {host} ({scanner[host].hostname()})")
        print(f"Estado: {scanner[host].state()}")
        
        for proto in scanner[host].all_protocols():
            print(f"Protocolo: {proto.upper()}")

            lport = scanner[host][proto].keys()
            # Ordena as portas para uma visualização mais limpa
            for port in sorted(lport):
                port_info = scanner[host][proto][port]
                print(f"  Porta {port}: \t{port_info['state']} ({port_info['name']})")
    else:
        print("-" * 40)
        print(f"Host: {host} está {scanner[host].state()}")

print("-" * 40)
print("Scan concluído.")
