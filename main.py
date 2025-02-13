import nmap
from pymetasploit3.msfrpc import MsfRpcClient
import dig

nmapScan = nmap.PortScanner()

ip = dig.get_IP()
portmin = "0"
portmax = "50"


###check multiple IPS
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