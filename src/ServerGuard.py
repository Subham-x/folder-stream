import http.server
import threading
import time
import os
import subprocess

from collections import defaultdict, deque

# ==============================
# Security Config
# ==============================

MAX_REQUESTS = 100
RATE_WINDOW = 5

ALLOWED_METHODS = ["GET", "HEAD"]

SUSPICIOUS_UA = [
    "sqlmap",
    "nmap",
    "nikto",
    "masscan",
    "curl",
    "wget",
    "python-requests",
]

TRAVERSAL_PATTERNS = [
    "../",
    "..\\",
    "%2e%2e",
    "system32",
]

# ==============================
# Runtime State
# ==============================

approved_ips = set()
blocked_ips = set()
pending_approvals = set()

request_log = defaultdict(deque)

lock = threading.Lock()


class GuardedHandler(http.server.SimpleHTTPRequestHandler):

    def log_message(self, format, *args):
        return

    def notify_windows_alert(self, ip):
        """Show an informational Windows Popup."""
        try:
            script = f"""
            [System.Windows.MessageBox]::Show('New connection request from {ip}. Please check the terminal to approve/deny.', 'Security Alert', 'OK', 'Information')
            """
            cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-Command", "Add-Type -AssemblyName PresentationFramework;", script]
            # Run in background so it doesn't block the terminal
            subprocess.Popen(cmd)
        except:
            pass

    def list_directory(self, path):
        try:
            items_list = os.listdir(path)
        except OSError:
            self.send_error(404, "No permission to list directory")
            return None

        items_list.sort(key=lambda a: a.lower())

        # Prepare Breadcrumb
        rel_path = os.path.relpath(path, os.getcwd())
        if rel_path == ".":
            display_path = "/"
            parts = []
        else:
            display_path = "/" + rel_path.replace("\\", "/")
            parts = rel_path.split(os.sep)

        breadcrumb_html = '<a href="/">Root</a>'
        current_acc = ""
        for part in parts:
            if not part: continue
            current_acc += "/" + part
            breadcrumb_html += f' <span>/</span> <a href="{current_acc}">{part}</a>'

        # Prepare Items
        items_html = ""

        # Add "Parent Directory" if not root
        if rel_path != ".":
            parent = os.path.dirname(display_path)
            items_html += f'<div class="item item-parent"><a href="{parent}"><span class="icon">🔙📁</span><span class="name">.. (Parent Directory)</span></a></div>'

        for name in items_list:
            fullname = os.path.join(path, name)
            displayname = linkname = name

            icon = "📄"
            if os.path.isdir(fullname):
                icon = "📁"
                displayname = name + "/"
                linkname = name + "/"
            elif name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp')):
                icon = "🖼️"
            elif name.lower().endswith(('.mp4', '.mkv', '.avi', '.mov')):
                icon = "🎬"
            elif name.lower().endswith(('.mp3', '.wav', '.flac')):
                icon = "🎵"
            elif name.lower().endswith(('.zip', '.rar', '.7z', '.tar', '.gz')):
                icon = "📦"

            items_html += f"""
            <div class="item">
                <a href="{linkname}">
                    <span class="icon">{icon}</span>
                    <span class="name">{name}</span>
                </a>
            </div>"""

        # Read and inject into template
        try:
            template_path = os.path.join(os.path.dirname(__file__), "template.html")
            with open(template_path, "r", encoding="utf-8") as f:
                html = f.read()

            html = html.replace("{directory}", display_path)
            html = html.replace("{breadcrumb}", breadcrumb_html)
            html = html.replace("{items}", items_html)

            encoded = html.encode("utf-8", "surrogateescape")
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return None # We handled the output
        except Exception as e:
            self.send_error(500, str(e))
            return None

    def approve_ip(self, ip):

        # 1. Quick check
        with lock:
            if ip in approved_ips:
                return True
            if ip in blocked_ips:
                return False
            if ip in pending_approvals:
                return False
            pending_approvals.add(ip)

        # 2. Notify and Ask

        print(f"!!! ACCESS REQUEST: {ip}")


        # Send non-blocking alert to Windows
        self.notify_windows_alert(ip)

        # Terminal input
        ans = input(f"Allow access for {ip}? (y/n) : ").lower().strip()
        ans_bool = (ans == "y")

        # 3. Update state
        with lock:
            pending_approvals.remove(ip)
            if ans_bool:
                approved_ips.add(ip)
                print(f"[APPROVED] {ip}")
                return True
            else:
                blocked_ips.add(ip)
                print(f"[DENIED] {ip}")
                return False

    def check_rate_limit(self, ip):

        now = time.time()
        q = request_log[ip]
        q.append(now)

        while q and now - q[0] > RATE_WINDOW:
            q.popleft()

        if len(q) > MAX_REQUESTS:
            # Better availability: Block the IP instead of killing the whole server
            self.suspicious(f"Request flood ({len(q)} req/{RATE_WINDOW}s)", ip)
            return False
        return True

    def suspicious(self, reason, ip):

        with lock:
            if ip not in blocked_ips:
                print(f"\n[BLOCKED] {ip}")
                print(f"Reason : {reason}")
                blocked_ips.add(ip)

    def kill_server(self, reason):

        print("\n===================================")
        print("SERVER STOPPED (CRITICAL SECURITY)")
        print(f"Reason : {reason}")
        print("===================================\n")

        os._exit(1)

    def check_suspicious(self, ip):

        ua = self.headers.get("User-Agent", "").lower()
        path = self.path.lower()

        for bad in SUSPICIOUS_UA:
            if bad in ua:
                self.suspicious(f"Suspicious User-Agent : {ua}", ip)
                return False

        for bad in TRAVERSAL_PATTERNS:
            if bad in path:
                self.suspicious(f"Path Traversal Attempt : {path}", ip)
                # For high security, we still kill for traversal attempts
                self.kill_server(f"Traversal attack from {ip}")
                return False

        return True

    def validate(self):

        ip = self.client_address[0]

        with lock:
            if ip in blocked_ips:
                return False

        if self.command not in ALLOWED_METHODS:
            self.suspicious(f"Invalid HTTP Method : {self.command}", ip)
            return False

        if not self.approve_ip(ip):
            return False

        if not self.check_rate_limit(ip):
            return False

        return self.check_suspicious(ip)

    def do_GET(self):
        if self.path == "/__kill__":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"Server Stopping...")
            self.kill_server("Remote Kill Request")
            return

        if not self.validate():
            self.send_error(403)
            return

        super().do_GET()

    def do_HEAD(self):

        if not self.validate():
            self.send_error(403)
            return

        super().do_HEAD()

    # Block everything else

    def do_POST(self):
        self.send_error(405)

    def do_PUT(self):
        self.send_error(405)

    def do_DELETE(self):
        self.send_error(405)

    def do_PATCH(self):
        self.send_error(405)
