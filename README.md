usage: portscan.py [-h] [-a ADDRESS | -f FILE] [-t TRACEROUTE] [-m MAXHOPS]
                   [-p PORT] [-r RANGE]
                   {tcp,udp,icmp}

Port scanning.

positional arguments:
  {tcp,udp,icmp}        Specify the port scan protocol

optional arguments:
  -h, --help            show this help message and exit
  -a ADDRESS, --address ADDRESS
                        Host IP address/range
  -f FILE, --file FILE  Path to file containing IP addresses. Whitespace
                        separated files only.
  -t TRACEROUTE, --traceroute TRACEROUTE
                        Destination IP address
  -m MAXHOPS, --maxhops MAXHOPS
                        Specify maximum number of hops to perform in a
                        traceroute.
  -p PORT, --port PORT  Comma seperated port numbers e.g., 22,80,443
  -r RANGE, --range RANGE
                        Range of port numbers e.g., 0-65535
NOTE: Must be ran using sudo
