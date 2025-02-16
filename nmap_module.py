import nmap

nmapScan = nmap.PortScanner()

def scan(ips, portrange):
    results = {}
    for ip in ips:
        result = nmapScan.scan(ip, portrange)
        results[ip] = result

        print(f"Nmap: {result.get('nmap', {})}")
        print(f"Scan: {result.get('scan', {})}")

        if ip in result.get("scan", {}) and "tcp" in result["scan"][ip]:
            tcp_results = result["scan"][ip]["tcp"]
            print("Ports open:\n")

            for port, tcp_result in tcp_results.items():
                port_info = f"Port {port} - {tcp_result['state']}"

                if tcp_result.get("name"):
                    port_info += f", {tcp_result['name']}"
                if tcp_result.get("product"):
                    port_info += f", {tcp_result['product']}"
                if tcp_result.get("extrainfo"):
                    port_info += f", {tcp_result['extrainfo']}"

                print(port_info)
        else:
            print(f"No open TCP ports found for {ip}")

    return results
