import sys
import socket
import datetime
from concurrent.futures import ThreadPoolExecutor
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

# Dictionary for known ports
KNOWN_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    88: "Kerberos (KDC)",
    111: "rpcbind (NFS)",
    139: "NetBios",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MsSQL",
    2105: "Kerberos",
    3306: "MySQL",
    3389: "RDP",
    5985: "WinRM",
    8080: "HTTP-Alt"
}

def get_service_name(port):
    return KNOWN_PORTS.get(port)

def IdentifySystem(open_ports):
    #This function will be used to see if the system is windows or linux
    port_db = {
        "linux": {
            22: 3.0,    # SSH (very strong Linux indicator)
            111: 2.0,   # RPCBind
            631: 1.5,   # CUPS printing
            3306: 1.0,  # MySQL
            5900: 1.0,  # VNC
            873: 1.0    # rsync
        },
        "windows": {
            3389: 3.0,  # RDP (strong Windows indicator)
            445: 2.5,   # SMB
            135: 2.0,   # MSRPC
            1433: 1.5,  # SQL Server
            5985: 1.5,  # WinRM
            139: 1.0    # NetBIOS
        }
    }
     
    scores = {"linux": 0.0, "windows": 0.0}
    for port in open_ports:
        # Check Linux ports
        for p, weight in port_db["linux"].items():
            if port == p:
                scores["linux"] += weight
                
        # Check Windows ports
        for p, weight in port_db["windows"].items():
            if port == p:
                scores["windows"] += weight

    if scores["linux"] > scores["windows"]:
        return ("linux")
    else:
        return ("windows")

def generate_pdf(ip, open_ports, scan_time):
    filename = f"port_scan_{ip.replace('.', '_')}.pdf"
    c = canvas.Canvas(filename, pagesize=A4)
    
    # Cabeçalho
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 800, f"Scan Report: {ip}")
    c.setFont("Helvetica", 12)
    c.drawString(50, 780, f"Date: {scan_time}")
    
    # Lista de portas
    y_position = 750
    c.drawString(50, y_position, "Open Ports:")
    y_position -= 30
    
    for port in open_ports:
        service = get_service_name(port)
        c.drawString(70, y_position, f"• Port {port} ({service})")
        y_position -= 20
    
    os_name = IdentifySystem(open_ports)
    c.drawString(50, y_position, "System is likely {}".format(os_name))

    c.save()
    print(f"\n[+] Report PDF generated: {filename}")

def PortScanner(ip, r):
    verbose = True if "-v" in sys.argv else False
    open_ports = []

    print(f"Starting scan: {datetime.datetime.now().strftime("%H:%M:%S")}\n" + "-"*50)
    try:
        for port in r:
            s = socket.socket()
            socket.setdefaulttimeout(0.5)

                
            result = s.connect_ex((ip, port))


            if result == 0:
                if verbose:
                    print(f"[+] {port} ({get_service_name(port)}) Open")
                else:
                    print(f"[+] {port} Open")
                open_ports.append(port)
                
            elif result != 0 and len(r) == 1:
                print("[-] {} Closed".format(port))
            
            s.close()

        
        print("-"*50, "\nEnding Scan:", datetime.datetime.now().time())
        if "-pdf" in sys.argv:
                generate_pdf(ip, open_ports, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

    except KeyboardInterrupt:
        print("\nExiting.")
        sys.exit(1)
    except socket.error:
        print("\nHost is offline.")
        sys.exit(1)


    
def Usage():
    print("port_scanner.py <target_ip> [flags]\n"
    "Will scan from 0-65535 if -p or -r are not specified.\n"
    "-p: Specify a single port.\n"
    "-r: Specify range - {start}-{end}.\n"
    "-v: Verbose(Time of each scan)\n"
    "-h: Help page\n"
    "-pdf: Generates a pdf file containing the ouput")

def main():
    flags = ["-p", "-r", "-v", "-h", "-pdf"]

    #Check if we can run
    if len(sys.argv) < 2 or ("-p" in sys.argv and "-r" in sys.argv) or (
        "-h" in sys.argv) or sys.argv[1] in flags:
        Usage()
        sys.exit(1)

    ip = str(sys.argv[1])

    #if only the ip was specified we will run all ports we can
    if len(sys.argv) == 2:
        r = range(65535)
        PortScanner(ip, r)

    if "-p" in sys.argv:
        try:
            index = sys.argv.index("-p")
            r = int(sys.argv[index + 1])
            if 0 <= r <= 65535:
                r = [r]
                PortScanner(ip, r)
            else:
                print("Port must be between 0 and 65535")
                sys.exit(1)
        except (IndexError, ValueError):
            print("Invalid format. -p <port>")
            sys.exit(1)
    elif "-r" in sys.argv:
        try:
            index = sys.argv.index("-r")
            r = sys.argv[index + 1]
            start, end = map(int, r.split("-"))
            if start < 0 or end > 65535:
                print("Range is limited to 0-65535")
                sys.exit(1)
            r = range(start, end+1)
            PortScanner(ip, r)
        except (IndexError, ValueError):
            print("Invalid range format. -r {start}-{end}")
            sys.exit(1)
        finally:
            sys.exit()

if __name__ == "__main__":
    main()
