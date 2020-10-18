import ipaddress

def ip_range(start_ip, end_ip):
    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start
    ip_range = []

    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i-1] += 1
        ip_range.append(".".join(map(str, temp)))

    return ip_range

def port_range(start_ip, end_ip):
    return [int(i) for i in range(int(start_ip), int(end_ip) + 1)]

def ip(ip: str) -> list:
    if "/" in ip:
        return [str(i) for i in ipaddress.IPv4Network(ip)]
    elif "-" in ip:
        return ip_range(ip.split("-")[0], ip.split("-")[1])
    else:
        return [ip]

def port(port: str) -> list:
    if "-" in port:
        return port_range(port.split("-")[0], port.split("-")[1])
    else:
        return [int(p) for p in port.split(",")]