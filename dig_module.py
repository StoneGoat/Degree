import pydig

## Get specific record
def get_dns_records(domain, record_type):
    try:
        results = pydig.query(domain, record_type)
        return results
    except Exception as e:
        print(f"Error fetching {record_type} records: {e}")
        return None

## Get Ip of domain
def get_IP(domain):
    IPs = []
    record = get_dns_records(domain, 'A')
    for ip in record :
        IPs.append(ip)
        print('ip:' + ip)
    return IPs

#Check txt records
def checkForTXT(domain):
    record = get_dns_records(domain, 'TXT')
    if (record):
        print(record)
    else :
        print('No txt')
##CNAME function

##SRV function

##MX record
