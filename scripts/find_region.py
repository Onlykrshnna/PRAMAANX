import httpx
import ipaddress

r = httpx.get('https://ip-ranges.amazonaws.com/ip-ranges.json')
data = r.json()

target = ipaddress.ip_address('2406:da14:25a:5800:0:4ca9:7190:5da4')
for prefix in data.get('ipv6_prefixes', []):
    net = ipaddress.ip_network(prefix['ipv6_prefix'])
    if target in net:
        reg = prefix['region']
        srv = prefix.get('service')
        print(f"EXACT AWS REGION FOUND: {reg} (service: {srv})")
        break

