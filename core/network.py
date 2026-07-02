import time
import threading
import yaml
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.all import TLSClientHello

class ScapyInterceptor:
    def __init__(self, config_path="config/config.yaml"):
        # Load the network interface from your centralized config
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.interface = self.config['sandbox'].get('network_interface', 'vmnet1')
        self.captured_data = []
        self._stop_event = threading.Event()
        self.sniff_thread = None

        # Pre-load required application layers for accurate deep packet inspection
        scapy.load_layer("http")
        scapy.load_layer("tls")

    def _packet_handler(self, packet):
        """Callback function to dissect packets as they arrive in real-time."""
        if not packet.haslayer(scapy.IP):
            return

        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        timestamp = time.strftime("%H:%M:%S")

        # ------------------------------------------
        # 1. Parse DNS Queries
        # ------------------------------------------
        if packet.haslayer(scapy.DNSQR):
            try:
                qname = packet[scapy.DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                self.captured_data.append({
                    "time": timestamp, "type": "DNS_QUERY", 
                    "src": src_ip, "dst": dst_ip, "detail": f"Requested: {qname}"
                })
            except Exception:
                pass

        # ------------------------------------------
        # 2. Parse TCP & Application Layer
        # ------------------------------------------
        elif packet.haslayer(scapy.TCP):
            sport = packet[scapy.TCP].sport
            dport = packet[scapy.TCP].dport
            flags = packet[scapy.TCP].flags

            # Capture Raw Connection Attempts
            if flags == 'S':
                self.captured_data.append({
                    "time": timestamp, "type": "TCP_SYN", 
                    "src": f"{src_ip}:{sport}", "dst": f"{dst_ip}:{dport}", 
                    "detail": "Connection Attempted"
                })

            # Capture HTTP Paths
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                if payload.startswith((b"GET ", b"POST ", b"PUT ")):
                    try:
                        first_line = payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                        self.captured_data.append({
                            "time": timestamp, "type": "HTTP_REQUEST", 
                            "src": f"{src_ip}:{sport}", "dst": f"{dst_ip}:{dport}", 
                            "detail": first_line
                        })
                    except Exception:
                        pass

            # Capture HTTPS TLS Negotiation (SNI Extraction)
            if packet.haslayer(TLSClientHello):
                try:
                    for ext in packet[TLSClientHello].ext:
                        if hasattr(ext, 'servernames'):
                            sni = ext.servernames[0].servername.decode('utf-8')
                            self.captured_data.append({
                                "time": timestamp, "type": "TLS_SNI", 
                                "src": f"{src_ip}:{sport}", "dst": f"{dst_ip}:{dport}", 
                                "detail": f"ClientHello SNI: {sni}"
                            })
                            break
                except Exception:
                    pass

    def _sniff_worker(self):
        """The blocking sniff function that runs in the background thread."""
        print(f"[*] Network Interceptor attached to interface: {self.interface}")
        try:
            # store=False prevents a memory leak during long analysis windows
            # stop_filter continuously checks if the stop event has been triggered by the main thread
            scapy.sniff(
                iface=self.interface, 
                prn=self._packet_handler, 
                store=False, 
                stop_filter=lambda p: self._stop_event.is_set()
            )
        except PermissionError:
            print("[-] FATAL: Scapy requires Administrator/Root privileges to sniff.")
        except Exception as e:
            print(f"[-] Scapy sniffer crashed: {e}")

    def start(self):
        """Spins up the background listener."""
        self._stop_event.clear()
        self.captured_data = [] # Reset data for a new run
        self.sniff_thread = threading.Thread(target=self._sniff_worker)
        self.sniff_thread.daemon = True # Ensures thread dies if main app crashes
        self.sniff_thread.start()

    def stop(self):
        """Kills the listener and returns the structured telemetry."""
        print("[*] Terminating network interceptor...")
        self._stop_event.set()
        if self.sniff_thread:
            self.sniff_thread.join(timeout=2) # 2-second timeout to prevent hanging
        return self.captured_data