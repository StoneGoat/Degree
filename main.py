from pymetasploit3.msfrpc import MsfRpcClient
import dig
import nmap_module

ips = dig.get_IP()
portmin = "0"
portmax = "50"


###check multiple IPS
portrange = f"{portmin}-{portmax}"

results = nmap_module.scan(ips, portrange)

