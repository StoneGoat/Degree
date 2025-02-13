import nmap
import pydig

nmapScan = nmap.PortScanner()

ip = "192.168.0.254"
portmin = "0"
portmax = "5000"

portrange = f"{portmin}-{portmax}"

result = nmapScan.scan(ip, portrange)

print(f"Nmap: {result["nmap"]}")
print(f"Scan: {result["scan"]}")
print(f"Tcp: {result["scan"][ip]["tcp"]}")

tcp_results = result["scan"][ip]["tcp"]

print("Ports open:\n")

for port in tcp_results:
    tcp_result = tcp_results[port]

    str = f"Port {port} - {tcp_result["state"]}"

    if (tcp_result["name"] != ""):
        str += f", {tcp_result["name"]}"

    if (tcp_result["product"] != ""):
        str += f", {tcp_result["product"]}"

    if (tcp_result["extrainfo"] != ""):
        str += f", {tcp_result["extrainfo"]}"

    print(str)