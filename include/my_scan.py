import random
from scapy.all import *

def tcp_scan(ips: list, ports:list):
    for host in ips:
        for dst_port in ports:
            src_port = random.randint(1025,65534)
            resp = sr1(
                IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,
                verbose=0,
            )

            if resp is None:
                print(f"{host}:{dst_port} is filtered.")

            elif(resp.haslayer(TCP)):
                if(resp.getlayer(TCP).flags == 0x12):
                    # Send a gratuitous RST to close the connection
                    send_rst = sr(
                        IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
                        timeout=1,
                        verbose=0,
                    )
                    print(f"{host}:{dst_port} is open.")

                elif (resp.getlayer(TCP).flags == 0x14):
                    print(f"{host}:{dst_port} is closed.")

            elif(resp.haslayer(ICMP)):
                if(
                    int(resp.getlayer(ICMP).type) == 3 and
                    int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
                ):
                    print(f"{host}:{dst_port} is filtered (silently dropped).")


def udp_scan(ips: list, ports:list):
    pass


def icmp_scan(ips: list):
    live_count = 0
    for host in ips:
        resp = sr1(
            IP(dst=str(host))/ICMP(),
            timeout=2,
            verbose=0,
        )

        if resp is None:
            print(f"{host} is down or not responding.")
        elif (
            int(resp.getlayer(ICMP).type)==3 and
            int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
        ):
            print(f"{host} is blocking ICMP.")
        else:
            print(f"{host} is responding.")
            live_count += 1

    print(f"{live_count}/{len(ips)} hosts are online.")