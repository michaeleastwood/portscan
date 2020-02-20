#!/usr/bin/python3
import socket
import subprocess
import sys
import os
import argparse
import ipaddress
from scapy.all import *

class NoHostError(Exception):
    pass

def file_path(string):
    if os.path.isfile(string):
        return string
    else:
        raise FileNotFoundError(string)

def main():
    # Specify commandline arguments 
    parser = argparse.ArgumentParser(description="Port scanning.")
    host_group = parser.add_mutually_exclusive_group()

    host_group.add_argument("-a", "--address",
                    type=str,
                    help="Host IP address/range")
    host_group.add_argument("-f", "--file",
                    type=file_path,
                    help="Path to file containing IP addresses. Whitespace separated files only.")
    parser.add_argument("-t", "--traceroute",
                    type=str,
                    help="Destination IP address")
    parser.add_argument("-m", "--maxhops",
                    type=int,
                    default=30,
                    help="Specify maximum number of hops to perform in a traceroute.")
    parser.add_argument("protocol",
                    type=str,
                    choices=["tcp", "udp", "icmp"],
                    help="Specify the port scan protocol")
    parser.add_argument("-p", "--port",
                    type=str,
                    help="Comma seperated port numbers e.g., 22,80,443")
    parser.add_argument("-r", "--range",
                    type=str,
                    default="0-65535",
                    help="Range of port numbers e.g., 0-65535")
    args = parser.parse_args()
    # Traceroute using udp, tcp, or icmp
    if args.traceroute:
        packet = None
        if args.protocol == "udp":
            packet = UDP(sport = RandShort(), dport=33434)
        elif args.protocol == "tcp":
            packet = TCP(seq=RandInt(), sport = RandShort(), dport=80)
        elif args.protocol == "icmp":
            packet = ICMP(id=os.getpid())
        a,b = sr(IP(dst=args.traceroute, ttl=(1,args.maxhops)) / packet, timeout=2)
        a = TracerouteResult(a.res)
        a.show()
        return
    
    # Parse commandline arguments for ports.
    ports = None
    if args.port:
        ports = set(map(int, args.port.split(",")))
    else:
        start,end = map(int, args.range.split("-"))
        ports = set(range(start, end+1))

    # Parse commandline arguments for ips
    ips = set()
    if args.address:
        ips = set(str(ip) for ip in ipaddress.IPv4Network(args.address))
        #print(ips)
        pass
    elif args.file:
        with open(args.file, "r") as file:
            data=file.read().split()
        for ip in data:
            ips.add(ip)
    else:
        raise NoHostError("No host address was specified, use args -a or -f")

    for ip in ips:
        # Iterate through all ips specified at runtime 
        open_ports = []
        closed_ports = 0
        for port in ports:
            # Iterate through all ports specified at runtime
            if args.protocol == "icmp":
                print("Port scanning is not permitted using ICMP... Defaulting to TCP.")
                args.protocol = "tcp"
            protocol = socket.SOCK_STREAM if args.protocol == "tcp" else socket.SOCK_DGRAM
            sock = socket.socket(socket.AF_INET, protocol)
            try:
                if args.protocol == "udp":
                    # Using scapy, scan port using udp
                    pkt = sr1(IP(dst=ip)/UDP(sport=port, dport=port), timeout=2, verbose=0)
                    if pkt == None:
                        print_ports(port, "Open / filtered")
                    else:
                        if pkt.haslayer(ICMP):
                            closed_port += 1
                        elif pkt.haslayer(UDP):
                            open_ports.append((port,""))
                        else:
                            pass
                elif args.protocol == "tcp":
                    # Using sockets, scan port using tcp
                    sock.settimeout(.1)                
                    sock.connect((ip, port))
                    try:
                        port_type = socket.getservbyport(port)
                        open_ports.append((port,port_type))
                    except:
                        # No service name availabe.
                        open_ports.append((port,""))
                        continue
                    sock.shutdown(socket.SHUT_RDWR)
            except (socket.timeout, ConnectionRefusedError) as ex:
                # Catch timeout and connection refused errors. 
                closed_ports += 1
                pass     
            except Exception as ex:
                # Catch miscellaneous exceptions
                template = "An exception of type {0} occurred. Arguments:\n{1!r}"
                message = template.format(type(ex).__name__, ex.args)
                #print(message)
                pass
            finally:
                sock.close()
        print(ip,":")
        print(closed_ports, "closed ports.")
        print("PORT\t\tSTATE\tSERVICE")
        # Print out open ports and services
        for port,port_type in open_ports:
            print(f"{port}/{args.protocol}   \topen\t{port_type}")
if __name__ == "__main__":
    main()
