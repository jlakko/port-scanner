# Port Scanner

My Port Scanner for IT&C 567.

This scanner is written in Python 3 and uses the Scapy module.

Help contents:
```
$ sudo python3 port-scanner.py -h
usage: port-scanner.py [-h] [-hn HOSTNAME] [-ip IP] [-p PORT] [-t] [-u] [-i] [-T] [-P PDF]

Port scanner.

optional arguments:
  -h, --help            show this help message and exit
  -hn HOSTNAME, --hostname HOSTNAME
                        Hostname to be scanned.
  -ip IP, --ip IP       IP(s) to be scanned.
  -p PORT, --port PORT  Port(s) to be scanned.
  -t, --tcp             Will scan hosts and ports via TCP. This is default if no flags are specified.
  -u, --udp             Will scan hosts and ports via UDP.
  -i, --icmp            Will scan hosts via ICMP.
  -T, --traceroute      Will perform a traceroute on specified hosts.
  -P PDF, --pdf PDF     Save the outputs of the scan to a PDF a the specified filename.
```

Example commands:
TCP Scan:
`sudo python3 port-scanner.py -ip 192.168.207.7 -p 3-100`

UDP Scan:
`sudo python3 port-scanner.py -ip 192.168.207.7 -p 3-100 -u`

ICMP Scan:
`sudo python3 port-scanner.py -ip 192.168.207.0/26 -i`

Run an ICMP traceroute:
`sudo python3 port-scanner.py -ip 192.168.207.7 -T`

Run an ICMP traceroute and save the output to a PDF:
`sudo python3 port-scanner.py -ip 192.168.207.7 -T -P /home/TRResults.pdf`