# PortScanner
Standard port scanner

## Purpose
This project is simple yet important. I attempted to simulate some of nmaps core pricipals and flags I use when doing a port scan. I also implemented a function to generate a pdf file with the output

## Flags
port_scanner.py <target_ip> [flags]\n"
    Will scan from 0-65535 if -p or -r are not specified
    -p: Specify a single port.
    -r: Specify range - {start}-{end}
    -v: Verbose
    -h: Help page\n"
    -pdf: Generates a pdf file containing the ouput

I used the verbose flag to emulate a OS recognition via the services that network has available.

