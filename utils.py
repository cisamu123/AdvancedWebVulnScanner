'''
       ^ Author    : Cisamu
       ^ Name      : AdvancedWebVulnScanner
       ^ Github    : https://github.com/cisamu123
'''
def is_internal_ip(ip):
    internal_ips = [
        "127.0.0.1", "localhost", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
    ]
    for internal_ip in internal_ips:
        if ip.startswith(internal_ip):
            return True
    return False
