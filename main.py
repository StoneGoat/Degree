from pymetasploit3.msfrpc import MsfRpcClient
import dig_module
import nmap_module

target = 'horselaugh.com'

ips = dig_module.get_IP(target)
portmin = "0"
portmax = "50"


###check multiple IPS
portrange = f"{portmin}-{portmax}"

results = nmap_module.scan(ips, portrange)

