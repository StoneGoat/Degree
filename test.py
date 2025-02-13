import nmap

nmapScan = nmap.PortScanner()

result = nmapScan.scan("127.0.0.1", "21-443")