import nmap 
#Create a nmap instance scanner
scanner = nmap.PortScanner()
# Perform a TCP connect scan on a target host
target = input("Tell me what is your target: ")
scanner.scan(target, arguments= "-sT")
#Print open ports and associated services
for host in scanner.all_hosts():
    print(f"host: {host} ({scanner[host].hostname()})")
    for proto in scanner[host].all_protocols():
        print(f"Protocol : {proto}")
        lport = scanner[host][proto].keys()
              for port in lport:
                print(f"{port}: {scanner[host][proto][port]['name']}")
        