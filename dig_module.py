import pydig

def get_dns_records(domain, record_type):
    try:
        results = pydig.query(domain, record_type)
        return results
    except Exception as e:
        print(f"Error fetching {record_type} records: {e}")
        return None

def get_IP(domain):
    IPs = []
    record = get_dns_records(domain, 'A')
    for ip in record :
        IPs.append(ip)
        print('ip:' + ip)
    return IPs