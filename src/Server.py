import socketserver
import socket
import os
import subprocess
import qrcode

from ServerGuard import GuardedHandler


PORT = 8000
VERSION = 2.4
CHANGELOG = "Updated Security layer"


# ==============================
# Firewall
# ==============================

def allow_firewall():

    try:

        subprocess.run([
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=PythonServe",
            "dir=in",
            "action=allow",
            "protocol=TCP",
            f"localport={PORT}"
        ], shell=True)

    except:
        pass


# ==============================
# LAN IP
# ==============================

def get_local_ip():

    try:

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        s.connect(("8.8.8.8", 80))

        ip = s.getsockname()[0]

        s.close()

        return ip

    except:
        return socket.gethostbyname(socket.gethostname())


# ==============================
# QR Terminal
# ==============================

def print_qr_terminal(text):

    qr = qrcode.QRCode(border=1)

    qr.add_data(text)

    qr.make(fit=True)

    matrix = qr.get_matrix()

    print()

    for y in range(0, len(matrix), 2):

        line = ""

        for x in range(len(matrix[0])):

            top = matrix[y][x]

            bottom = False

            if y + 1 < len(matrix):
                bottom = matrix[y + 1][x]

            if top and bottom:
                line += "█"

            elif top and not bottom:
                line += "▀"

            elif not top and bottom:
                line += "▄"

            else:
                line += " "

        print(line)

    print()


# ==============================
# TCP Server
# ==============================

class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


# ==============================
# Main
# ==============================

if __name__ == "__main__":

    allow_firewall()

    ip = get_local_ip()

    url = f"http://{ip}:{PORT}"

    print("\n===================================")
    print(f"Version   : {VERSION}")
    print(f"Changelog : {CHANGELOG}")
    print("...................................")
    print("Serving Folder:")
    print(os.getcwd())
    print()
    print(f"LOCAL : http://localhost:{PORT}")
    print(f"LAN   : {url}")
    print("===================================")

    # print("\nSecurity:")
    # print("✔ LAN only")
    # print("✔ IP approval")
    # print("✔ request rate limit")
    # print("✔ path traversal block")
    # print("✔ suspicious auto shutdown")
    # print("✔ whitelist cache")
    # print("✔ firewall rule")
    # print("✔ QR")

    print("\nScan QR:\n")

    print_qr_terminal(url)

    with ReusableTCPServer(("", PORT), GuardedHandler) as httpd:

        print("\nServer running...\n")

        httpd.serve_forever()
