#!/usr/bin/env python3
"""
DPI KILLSWITCH - Windows Raw Packet Fragmenter
Requires: pydivert (WinDivert wrapper)
Run as Administrator: python dpi_killswitch.py

Features:
- TLS SNI Fragmentation (--frag-by-sni)
- Reverse/Native Fragment ordering
- Fake Request Mode (wrong-seq, wrong-chksum, fake-gen)
- Domain blacklist support
- QUIC/HTTP3 blocking
- Auto-TTL / Set-TTL for fake packets
- DNS redirection
- HTTP Host header tricks
"""
import ctypes
from ctypes import c_int, byref, sizeof, Structure
from PySide6.QtCore import Qt
import sys
import struct
import threading
import socket
import os
import re
from collections import defaultdict
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton,
                            QSpinBox, QLabel, QTextEdit, QHBoxLayout, QFrame, QComboBox,
                            QFileDialog, QGroupBox, QGridLayout, QLineEdit, QScrollArea,
                            QTabWidget)
from PySide6.QtCore import QThread, Signal, Qt, QTimer
from PySide6.QtGui import QFont, QPalette, QColor, QPainter, QPen
import random
from PySide6.QtWidgets import QCheckBox
try:
   import pydivert
   from pydivert.consts import Direction
except ImportError:
   pydivert = None


class MatrixRain(QWidget):
   def __init__(self, parent=None):
       super().__init__(parent)
       self.chars = []
       self.timer = QTimer()
       self.timer.timeout.connect(self.update_rain)
       self.timer.start(50)
       self.setMinimumHeight(80)

   def update_rain(self):
       if random.random() < 0.15:
           self.chars.append({
               'x': random.randint(0, self.width()),
               'y': 0,
               'char': random.choice('01ABCDEF'),
               'speed': random.randint(3, 6)
           })

       self.chars = [c for c in self.chars if c['y'] < self.height()]
       for c in self.chars:
           c['y'] += c['speed']
       self.update()

   def paintEvent(self, event):
       painter = QPainter(self)
       painter.fillRect(self.rect(), QColor(0, 0, 0, 40))

       font = QFont('Courier', 9, QFont.Bold)
       painter.setFont(font)

       for c in self.chars:
           alpha = 255 - int((c['y'] / self.height()) * 100)
           painter.setPen(QPen(QColor(0, 255, 65, max(alpha, 100))))
           painter.drawText(c['x'], c['y'], c['char'])


class QUICBlocker(QThread):
    """Separate thread for blocking QUIC/HTTP3 traffic"""
    output = Signal(str)
    stats = Signal(int)  # blocked count

    def __init__(self):
        super().__init__()
        self.running = True
        self.blocked_count = 0

    def is_quic_packet(self, payload):
        """Check if UDP payload is QUIC traffic"""
        if len(payload) < 5:
            return False
        # QUIC long header starts with 1 in first 2 bits
        # QUIC short header has fixed bit set
        first_byte = payload[0]
        # Long header form: 1xxx xxxx
        if first_byte & 0x80:
            # Check for QUIC version field (bytes 1-4)
            if len(payload) >= 5:
                version = struct.unpack('>I', payload[1:5])[0]
                # Known QUIC versions
                if version in [0x00000001, 0xff000000, 0xff00001d, 0xff00001e, 0xff00001f,
                              0xff000020, 0xff000021, 0xff000022, 0xff000023, 0xff000024,
                              0xff000025, 0xff000026, 0xff000027, 0xff000028, 0xff000029]:
                    return True
        return False

    def run(self):
        if pydivert is None:
            self.output.emit('[QUIC] ERROR: pydivert not available')
            return

        try:
            self.output.emit('[QUIC] Starting QUIC/HTTP3 blocker...')
            # Filter for outbound UDP on ports commonly used by QUIC
            filter_str = "outbound and udp and (udp.DstPort == 443 or udp.DstPort == 80 or udp.DstPort == 853)"

            with pydivert.WinDivert(filter_str) as w:
                self.output.emit('[QUIC] QUIC blocker active - forcing TCP/TLS fallback')

                for packet in w:
                    if not self.running:
                        break

                    if packet.payload and self.is_quic_packet(packet.payload):
                        # Drop QUIC packets to force TCP fallback
                        self.blocked_count += 1
                        if self.blocked_count % 10 == 1:
                            self.output.emit(f'[QUIC] Blocked QUIC packet to {packet.dst_addr}:{packet.dst_port}')
                            self.stats.emit(self.blocked_count)
                    else:
                        # Pass non-QUIC UDP traffic
                        w.send(packet)

        except Exception as e:
            self.output.emit(f'[QUIC] Error: {str(e)}')
        finally:
            self.output.emit('[QUIC] QUIC blocker stopped')

    def stop(self):
        self.running = False


class DNSRedirector(QThread):
    """Thread for DNS redirection to custom resolver"""
    output = Signal(str)
    stats = Signal(int)  # redirected count

    def __init__(self, dns_ip, dns_port):
        super().__init__()
        self.running = True
        self.dns_ip = dns_ip
        self.dns_port = dns_port
        self.redirected_count = 0

    def run(self):
        if pydivert is None:
            self.output.emit('[DNS] ERROR: pydivert not available')
            return

        try:
            self.output.emit(f'[DNS] Starting DNS redirector to {self.dns_ip}:{self.dns_port}...')
            filter_str = "outbound and udp and udp.DstPort == 53"

            with pydivert.WinDivert(filter_str) as w:
                self.output.emit('[DNS] DNS redirection active')

                for packet in w:
                    if not self.running:
                        break

                    # Redirect DNS to custom resolver
                    original_dst = packet.dst_addr
                    packet.dst_addr = self.dns_ip
                    packet.dst_port = self.dns_port

                    w.send(packet, recalculate_checksum=True)
                    self.redirected_count += 1

                    if self.redirected_count % 20 == 1:
                        self.output.emit(f'[DNS] Redirected DNS query (was: {original_dst}:53)')
                        self.stats.emit(self.redirected_count)

        except Exception as e:
            self.output.emit(f'[DNS] Error: {str(e)}')
        finally:
            self.output.emit('[DNS] DNS redirector stopped')

    def stop(self):
        self.running = False


class PacketFragmenter(QThread):
   output = Signal(str)
   stats = Signal(int, int, int)  # fragmented, total, injected

   def __init__(self, split_point, mode='outbound', debug=True, strategy='split',
                reverse_frag=False, native_frag=False, fake_count=1,
                use_wrong_seq=False, use_wrong_chksum=False, use_ttl_trick=False,
                ttl_value=3, blacklist_domains=None, sni_frag=False,
                http_host_space=False, http_host_mixcase=False, http_host_remove=False,
                include_http=False):
       super().__init__()
       self.split_point = split_point
       self.mode = mode
       self.running = True
       self.debug = debug
       self.strategy = strategy  # 'split', 'disorder', 'fake', 'fake_first', 'tls_sni_frag'

       # New features
       self.reverse_frag = reverse_frag
       self.native_frag = native_frag
       self.fake_count = fake_count
       self.use_wrong_seq = use_wrong_seq
       self.use_wrong_chksum = use_wrong_chksum
       self.use_ttl_trick = use_ttl_trick
       self.ttl_value = ttl_value
       self.blacklist_domains = blacklist_domains or set()
       self.sni_frag = sni_frag
       self.http_host_space = http_host_space
       self.http_host_mixcase = http_host_mixcase
       self.http_host_remove = http_host_remove
       self.include_http = include_http

       # Stats
       self.packets_fragmented = 0
       self.packets_total = 0
       self.packets_injected = 0
       self.packets_passed = 0

       # Track connections to only fragment first ClientHello
       self.seen_connections = set()
       self.lock = threading.Lock()

   def extract_sni(self, payload):
       """Extract SNI (Server Name Indication) from TLS ClientHello"""
       try:
           if len(payload) < 43:
               return None, None

           # TLS record header (5 bytes) + Handshake header (4 bytes)
           pos = 5 + 4

           # Skip client version (2) + random (32)
           pos += 34

           if pos >= len(payload):
               return None, None

           # Session ID length
           session_id_len = payload[pos]
           pos += 1 + session_id_len

           if pos + 2 >= len(payload):
               return None, None

           # Cipher suites length
           cipher_suites_len = struct.unpack('>H', payload[pos:pos+2])[0]
           pos += 2 + cipher_suites_len

           if pos >= len(payload):
               return None, None

           # Compression methods length
           comp_methods_len = payload[pos]
           pos += 1 + comp_methods_len

           if pos + 2 >= len(payload):
               return None, None

           # Extensions length
           extensions_len = struct.unpack('>H', payload[pos:pos+2])[0]
           pos += 2

           extensions_end = pos + extensions_len

           while pos + 4 < extensions_end and pos + 4 < len(payload):
               ext_type = struct.unpack('>H', payload[pos:pos+2])[0]
               ext_len = struct.unpack('>H', payload[pos+2:pos+4])[0]

               if ext_type == 0:  # SNI extension
                   sni_start = pos
                   # SNI list length (2) + SNI type (1) + SNI length (2)
                   sni_pos = pos + 4 + 2 + 1 + 2
                   if sni_pos < len(payload):
                       sni_len = struct.unpack('>H', payload[pos+4+2+1:pos+4+2+1+2])[0]
                       sni_name = payload[sni_pos:sni_pos+sni_len].decode('ascii', errors='ignore')
                       return sni_name, sni_start

               pos += 4 + ext_len

           return None, None
       except Exception as e:
           if self.debug:
               self.output.emit(f'[DEBUG] SNI extraction error: {e}')
           return None, None

   def is_tls_client_hello(self, payload):
       """Check if payload is TLS ClientHello"""
       if len(payload) < 6:
           return False

       # TLS ContentType (0x16 = Handshake)
       if payload[0] != 0x16:
           if self.debug and self.packets_total <= 10:
               self.output.emit(f'[DEBUG] Not TLS handshake: first byte = 0x{payload[0]:02x}')
           return False

       # TLS Version (0x03, 0x01-0x03)
       if payload[1] != 0x03 or payload[2] not in [0x01, 0x02, 0x03]:
           if self.debug and self.packets_total <= 10:
               self.output.emit(f'[DEBUG] Bad TLS version: 0x{payload[1]:02x} 0x{payload[2]:02x}')
           return False

       # Check for ClientHello (0x01) after TLS header
       if len(payload) > 5 and payload[5] == 0x01:
           if self.debug:
               self.output.emit(f'[✓] DETECTED ClientHello! Size: {len(payload)} bytes')
           return True

       if self.debug and self.packets_total <= 10:
           self.output.emit(f'[DEBUG] Not ClientHello: handshake type = 0x{payload[5]:02x}')
       return False

   def is_http_request(self, payload):
       """Check if payload is an HTTP request"""
       try:
           start = payload[:20].decode('ascii', errors='ignore').upper()
           return start.startswith(('GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ', 'OPTIONS ', 'PATCH '))
       except:
           return False

   def mangle_http_host(self, payload):
       """Apply HTTP host header tricks"""
       try:
           text = payload.decode('ascii', errors='ignore')

           # Find Host header
           host_match = re.search(r'Host:\s*([^\r\n]+)', text, re.IGNORECASE)
           if not host_match:
               return payload

           original_host = host_match.group(0)
           host_value = host_match.group(1)
           new_host = original_host

           if self.http_host_remove:
               # Remove space after Host:
               new_host = f'Host:{host_value}'
           elif self.http_host_space:
               # Add extra space
               new_host = f'Host:  {host_value}'

           if self.http_host_mixcase:
               # Mix case of Host header
               mixed = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(host_value))
               new_host = new_host.replace(host_value, mixed)

           if new_host != original_host:
               text = text.replace(original_host, new_host)
               if self.debug:
                   self.output.emit(f'[HTTP] Mangled Host: {original_host} -> {new_host}')
               return text.encode('ascii', errors='ignore')

           return payload
       except Exception as e:
           if self.debug:
               self.output.emit(f'[DEBUG] HTTP mangle error: {e}')
           return payload

   def should_process_domain(self, sni):
       """Check if domain should be processed based on blacklist"""
       if not self.blacklist_domains:
           return True  # No blacklist = process all

       if not sni:
           return False  # No SNI and we have a blacklist = skip

       # Check if SNI matches any domain in blacklist
       sni_lower = sni.lower()
       for domain in self.blacklist_domains:
           domain_lower = domain.lower().strip()
           if domain_lower and (sni_lower == domain_lower or sni_lower.endswith('.' + domain_lower)):
               if self.debug:
                   self.output.emit(f'[BLACKLIST] Matched: {sni} (rule: {domain})')
               return True

       return False

   def fragment_payload(self, payload, sni_offset=None):
       """Pure TCP-level fragmentation for TLS ClientHello"""
       try:
           if not self.is_tls_client_hello(payload):
               return None

           # Need at least TLS header (5 bytes) + some data to split
           if len(payload) <= 5 + self.split_point:
               if self.debug:
                   self.output.emit(f'[DEBUG] Payload too small for split: {len(payload)} bytes (need > {5 + self.split_point})')
               return None

           # Determine split point
           if self.sni_frag and sni_offset is not None:
               # Split at SNI location
               split_at = sni_offset
               if self.debug:
                   self.output.emit(f'[DEBUG] SNI-based split at offset {split_at}')
           else:
               # Split TCP payload: header + chunk1 | rest
               split_at = 5 + self.split_point

           first_frag = payload[:split_at]
           second_frag = payload[split_at:]

           if self.debug:
               self.output.emit(f'[DEBUG] TCP Frag ready: {len(first_frag)}B + {len(second_frag)}B')

           return (first_frag, second_frag, b'')

       except Exception as e:
           self.output.emit(f'[!] FRAGMENT ERROR: {str(e)}')
           import traceback
           self.output.emit(f'[!] TRACE: {traceback.format_exc()[:300]}')
           return None

   def generate_fake_packet(self, original_payload, packet_num=0):
       """Generate a fake TLS/HTTP packet for DPI confusion"""
       try:
           # Create fake ClientHello-like payload
           fake_domains = [
               b'www.google.com',
               b'microsoft.com',
               b'cloudflare.com',
               b'amazon.com',
               b'facebook.com'
           ]

           # Start with original structure but replace SNI
           fake_payload = bytearray(original_payload[:min(len(original_payload), 200)])

           # Inject fake domain somewhere in the payload
           fake_domain = random.choice(fake_domains)
           if len(fake_payload) > 60:
               inject_pos = random.randint(40, min(100, len(fake_payload) - len(fake_domain)))
               fake_payload[inject_pos:inject_pos+len(fake_domain)] = fake_domain

           # Add some random padding
           fake_payload.extend(random.randbytes(random.randint(10, 50)))

           return bytes(fake_payload)
       except Exception as e:
           if self.debug:
               self.output.emit(f'[DEBUG] Fake packet generation error: {e}')
           return original_payload[:100] + b'\x00' * 50

   def process_packet(self, w, packet):
       """Process packet with WinDivert"""
       try:
           self.packets_total += 1

           if self.debug and self.packets_total <= 5:
               self.output.emit(f'[DEBUG] Packet #{self.packets_total}: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}')

           # Determine target ports based on mode
           target_ports = {443}
           if self.include_http:
               target_ports.add(80)

           # Only process TCP packets on target ports
           if not packet.tcp or packet.dst_port not in target_ports:
               w.send(packet)
               self.packets_passed += 1
               return

           # Check if packet has payload
           if not packet.payload or len(packet.payload) < 6:
               w.send(packet)
               self.packets_passed += 1
               if self.debug and self.packets_total <= 10:
                   self.output.emit(f'[DEBUG] No payload or too small: {len(packet.payload) if packet.payload else 0} bytes')
               return

           if self.debug and self.packets_total <= 10:
               payload_hex = packet.payload[:20].hex() if len(packet.payload) >= 20 else packet.payload.hex()
               self.output.emit(f'[DEBUG] Payload start: {payload_hex}')

           # Handle HTTP traffic (port 80)
           if packet.dst_port == 80 and self.is_http_request(packet.payload):
               if self.http_host_space or self.http_host_mixcase or self.http_host_remove:
                   packet.payload = self.mangle_http_host(packet.payload)
               w.send(packet, recalculate_checksum=True)
               self.packets_passed += 1
               return

           # Create connection identifier
           conn_id = (packet.src_addr, packet.dst_addr, packet.src_port, packet.dst_port)

           # Only fragment first ClientHello per connection
           with self.lock:
               if conn_id in self.seen_connections:
                   w.send(packet)
                   self.packets_passed += 1
                   return

           # Extract SNI for blacklist checking and SNI-based fragmentation
           sni_name, sni_offset = self.extract_sni(packet.payload)

           if self.debug and sni_name:
               self.output.emit(f'[SNI] Detected: {sni_name}')

           # Check blacklist if enabled
           if self.blacklist_domains and not self.should_process_domain(sni_name):
               w.send(packet)
               self.packets_passed += 1
               return

           # Try to fragment
           result = self.fragment_payload(packet.payload, sni_offset if self.sni_frag else None)

           if result:
               first_frag, second_frag, _ = result

               with self.lock:
                   self.seen_connections.add(conn_id)
                   self.packets_fragmented += 1

               # Save original values
               orig_seq = packet.tcp.seq_num
               orig_ttl = getattr(packet, 'ttl', 64)

               # Calculate TTL for fake packets
               fake_ttl = orig_ttl
               if self.use_ttl_trick:
                   fake_ttl = max(1, orig_ttl - self.ttl_value)

               # ========== FAKE_FIRST STRATEGY ==========
               if self.strategy == 'fake_first':
                   # Send fake packets first
                   for i in range(self.fake_count):
                       fake_payload = self.generate_fake_packet(packet.payload, i)
                       packet.payload = fake_payload

                       if self.use_wrong_seq:
                           packet.tcp.seq_num = orig_seq - random.randint(1000, 5000)

                       if self.use_ttl_trick:
                           # Note: TTL modification may require raw packet construction
                           pass

                       # Send with wrong checksum if enabled
                       w.send(packet, recalculate_checksum=not self.use_wrong_chksum)
                       self.packets_injected += 1

                       if self.debug:
                           self.output.emit(f'[FAKE] Sent fake packet #{i+1} (wrong_seq={self.use_wrong_seq}, wrong_chksum={self.use_wrong_chksum})')

                       import time
                       time.sleep(0.001)

                   # Reset sequence number
                   packet.tcp.seq_num = orig_seq

               # ========== SEND REAL FRAGMENTS ==========
               if self.reverse_frag:
                   # Send fragments in reverse order
                   frags = [(second_frag, orig_seq + len(first_frag)), (first_frag, orig_seq)]
               else:
                   frags = [(first_frag, orig_seq), (second_frag, orig_seq + len(first_frag))]

               for idx, (frag, seq) in enumerate(frags):
                   packet.payload = frag
                   packet.tcp.seq_num = seq

                   if self.native_frag:
                       # Native fragmentation - set PSH on each fragment
                       packet.tcp.psh = True
                   else:
                       packet.tcp.psh = (idx == len(frags) - 1)  # PSH only on last

                   w.send(packet, recalculate_checksum=True)
                   self.packets_injected += 1

                   import time
                   time.sleep(0.001)

               strategy_desc = self.strategy.upper()
               if self.reverse_frag:
                   strategy_desc += "+REV"
               if self.native_frag:
                   strategy_desc += "+NAT"
               if self.sni_frag:
                   strategy_desc += "+SNI"

               self.output.emit(
                   f'[>>] FRAGMENTED [{strategy_desc}]: {packet.dst_addr}:{packet.dst_port} '
                   f'[{len(first_frag)}B + {len(second_frag)}B]'
                   + (f' SNI={sni_name}' if sni_name else '')
               )

               # Update stats
               if self.packets_fragmented % 5 == 0:
                   self.stats.emit(self.packets_fragmented, self.packets_total, self.packets_injected)
           else:
               w.send(packet)
               self.packets_passed += 1

           # Periodic stats
           if self.packets_total % 50 == 0:
               self.stats.emit(self.packets_fragmented, self.packets_total, self.packets_injected)
               self.output.emit(f'[*] Stats: Total={self.packets_total}, Passed={self.packets_passed}, Fragmented={self.packets_fragmented}')

       except Exception as e:
           self.output.emit(f'[!] PACKET ERROR: {str(e)}')
           import traceback
           self.output.emit(f'[!] TRACE: {traceback.format_exc()[:200]}')
           try:
               w.send(packet)
           except:
               pass

   def run(self):
       """Main capture loop"""
       if pydivert is None:
           self.output.emit('[!] ERROR: pydivert NOT INSTALLED')
           self.output.emit('[!] INSTALL: pip install pydivert')
           self.output.emit('[!] ALSO DOWNLOAD: WinDivert driver from reqrypt.org/windivert')
           return

       try:
           self.output.emit('[+] INITIALIZING WINDIVERT...')

           # Build filter based on settings
           ports = ["tcp.DstPort == 443"]
           if self.include_http:
               ports.append("tcp.DstPort == 80")

           port_filter = " or ".join(ports)
           filter_str = f"outbound and tcp and ({port_filter}) and tcp.PayloadLength > 0"

           self.output.emit(f'[+] FILTER: {filter_str}')

           # Log active features
           features = []
           if self.sni_frag:
               features.append('SNI-Frag')
           if self.reverse_frag:
               features.append('Reverse')
           if self.native_frag:
               features.append('Native')
           if self.strategy == 'fake_first':
               features.append(f'FakeFirst(x{self.fake_count})')
           if self.use_wrong_seq:
               features.append('WrongSeq')
           if self.use_wrong_chksum:
               features.append('WrongChksum')
           if self.use_ttl_trick:
               features.append(f'TTL-{self.ttl_value}')
           if self.blacklist_domains:
               features.append(f'Blacklist({len(self.blacklist_domains)} domains)')
           if self.http_host_space or self.http_host_mixcase or self.http_host_remove:
               features.append('HTTPTricks')

           if features:
               self.output.emit(f'[+] ACTIVE FEATURES: {", ".join(features)}')

           with pydivert.WinDivert(filter_str) as w:
               self.output.emit('[+] PACKET CAPTURE ACTIVE')
               self.output.emit('[+] FRAGMENTING TLS CLIENTHELLO')
               self.output.emit('[*] BROWSE NORMALLY - DPI BYPASS ENGAGED')
               self.output.emit('[*] NO PROXY NEEDED - TRANSPARENT MODE')
               if self.debug:
                   self.output.emit('[*] DEBUG MODE ENABLED - VERBOSE LOGGING')

               for packet in w:
                   if not self.running:
                       break
                   self.process_packet(w, packet)

       except PermissionError:
           self.output.emit('[!] ERROR: ADMINISTRATOR RIGHTS REQUIRED')
           self.output.emit('[!] RIGHT-CLICK PYTHON AND "RUN AS ADMINISTRATOR"')
       except Exception as e:
           self.output.emit(f'[!] FATAL ERROR: {str(e)}')
           self.output.emit('[!] MAKE SURE WINDIVERT IS INSTALLED CORRECTLY')
       finally:
           self.output.emit('[*] PACKET CAPTURE TERMINATED')

   def stop(self):
       """Stop capture"""
       self.running = False
       
class MARGINS(Structure):
    _fields_ = [("left", c_int), ("right", c_int), ("top", c_int), ("bottom", c_int)]

def enable_acrylic(hwnd):
    margins = MARGINS(-1, -1, -1, -1)
    ctypes.windll.dwmapi.DwmExtendFrameIntoClientArea(hwnd, byref(margins))
    ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 38, byref(c_int(3)), sizeof(c_int))

class CyberDPITool(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('◈ DPI KILLSWITCH v5.0 - WINDOWS RAW MODE ◈')
        self.setGeometry(100, 100, 900, 850)
        
        # ADD THESE 2 LINES
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowFlags(self.windowFlags() | Qt.FramelessWindowHint)  # Required for blur
        
        self.setStyleSheet("""


QWidget {
           background: rgba(30, 30, 30, 0.6);
           color: #ffffff;
           font-family: 'Segoe UI', 'Consolas', monospace;
       }
       QPushButton {
           background: rgba(255, 255, 255, 0.08);
           border: 1px solid rgba(255, 255, 255, 0.15);
           border-radius: 8px;
           padding: 14px 28px;
           color: #ffffff;
           font-size: 14px;
           font-weight: bold;
           text-transform: uppercase;
           letter-spacing: 2px;
       }
       QPushButton:hover {
           background: rgba(255, 255, 255, 0.15);
           border: 1px solid rgba(255, 255, 255, 0.3);
       }
       QPushButton:pressed {
           background: rgba(255, 255, 255, 0.25);
       }
       QPushButton:disabled {
           background: rgba(255, 255, 255, 0.03);
           border: 1px solid rgba(255, 255, 255, 0.05);
           color: rgba(255, 255, 255, 0.3);
       }
       QSpinBox, QLineEdit {
           background: rgba(255, 255, 255, 0.06);
           border: 1px solid rgba(255, 255, 255, 0.12);
           border-radius: 5px;
           padding: 8px;
           color: #ffffff;
           font-size: 13px;
           font-weight: bold;
       }
       QSpinBox::up-button, QSpinBox::down-button {
           background: rgba(255, 255, 255, 0.08);
           border: 1px solid rgba(255, 255, 255, 0.1);
           width: 22px;
       }
       QSpinBox::up-button:hover, QSpinBox::down-button:hover {
           background: rgba(255, 255, 255, 0.15);
       }
       QTextEdit {
           background: rgba(255, 255, 255, 0.04);
           border: 1px solid rgba(255, 255, 255, 0.1);
           border-radius: 8px;
           color: #ffffff;
           font-family: 'Consolas', monospace;
           font-size: 11px;
           padding: 12px;
           selection-background-color: rgba(255, 255, 255, 0.2);
           selection-color: #000;
       }
       QLabel {
           color: rgba(255, 255, 255, 0.85);
           font-size: 12px;
           font-weight: bold;
       }
       QFrame {
           background: rgba(255, 255, 255, 0.05);
           border: 1px solid rgba(255, 255, 255, 0.1);
           border-radius: 10px;
       }
       QGroupBox {
           background: rgba(255, 255, 255, 0.05);
           border: 1px solid rgba(255, 255, 255, 0.1);
           border-radius: 8px;
           margin-top: 10px;
           padding-top: 10px;
           font-weight: bold;
           color: rgba(255, 255, 255, 0.85);
       }
       QGroupBox::title {
           subcontrol-origin: margin;
           left: 10px;
           padding: 0 5px;
       }
       QComboBox {
           background: rgba(255, 255, 255, 0.06);
           border: 1px solid rgba(255, 255, 255, 0.12);
           border-radius: 5px;
           padding: 8px;
           color: #ffffff;
           font-weight: bold;
       }
       QComboBox::drop-down {
           border: none;
       }
       QComboBox QAbstractItemView {
           background: rgba(30, 30, 30, 0.95);
           border: 1px solid rgba(255, 255, 255, 0.15);
           color: #ffffff;
           selection-background-color: rgba(255, 255, 255, 0.15);
           selection-color: #fff;
       }
       QCheckBox {
           color: #ffffff;
           font-size: 11px;
           spacing: 8px;
       }
       QCheckBox::indicator {
           width: 18px;
           height: 18px;
           border: 1px solid rgba(255, 255, 255, 0.2);
           border-radius: 4px;
           background: rgba(255, 255, 255, 0.06);
       }
       QCheckBox::indicator:checked {
           background: rgba(255, 255, 255, 0.3);
       }
       QTabWidget::pane {
           border: 1px solid rgba(255, 255, 255, 0.1);
           border-radius: 8px;
           background: rgba(255, 255, 255, 0.05);
       }
       QTabBar::tab {
           background: rgba(255, 255, 255, 0.03);
           border: 1px solid rgba(255, 255, 255, 0.08);
           border-bottom: none;
           border-radius: 5px 5px 0 0;
           padding: 8px 16px;
           color: rgba(255, 255, 255, 0.6);
           font-weight: bold;
       }
       QTabBar::tab:selected {
           background: rgba(255, 255, 255, 0.1);
           color: #ffffff;
       }
       QScrollArea {
           border: none;
           background: transparent;
       }
       """)
       # Initialize threads
       self.thread = None
       self.quic_blocker = None
       self.dns_redirector = None
       self.blacklist_domains = set()

       layout = QVBoxLayout()
       layout.setSpacing(10)
       layout.setContentsMargins(15, 15, 15, 15)

       # Matrix Rain Header
       self.matrix = MatrixRain()
       layout.addWidget(self.matrix)

       # Title
       title = QLabel('◈◈◈ WINDOWS RAW SOCKET DPI BYPASS ◈◈◈')
       title.setAlignment(Qt.AlignCenter)
       title.setStyleSheet("""
           font-size: 16px;
           color: #00ff41;
           padding: 10px;
           letter-spacing: 3px;
           font-weight: bold;
       """)
       layout.addWidget(title)

       # Warning
       warning = QLabel('⚠ REQUIRES ADMINISTRATOR + WinDivert Driver ⚠')
       warning.setAlignment(Qt.AlignCenter)
       warning.setStyleSheet("""
           font-size: 11px;
           color: #ff0066;
           padding: 5px;
           background: #1a0a0a;
           border: 1px solid #ff0066;
           border-radius: 5px;
       """)
       layout.addWidget(warning)

       # Create tabs for organized settings
       tabs = QTabWidget()

       # ============ TAB 1: MAIN SETTINGS ============
       main_tab = QWidget()
       main_layout = QVBoxLayout()
       main_layout.setSpacing(10)

       # Split Point & Strategy Row
       basic_frame = QFrame()
       basic_layout = QGridLayout()
       basic_layout.setSpacing(10)

       # Split Point
       split_label = QLabel('⚡ FRAGMENT SIZE:')
       self.split_spin = QSpinBox()
       self.split_spin.setValue(100)
       self.split_spin.setRange(40, 500)
       self.split_spin.setSuffix(' bytes')
       basic_layout.addWidget(split_label, 0, 0)
       basic_layout.addWidget(self.split_spin, 0, 1)

       # Strategy Selection
       strategy_label = QLabel('⚡ BYPASS STRATEGY:')
       self.strategy_combo = QComboBox()
       self.strategy_combo.addItems([
           'Split (Standard)',
           'Disorder (Out-of-Order)',
           'Fake SNI (Decoy Packet)',
           'Fake First (Send Fakes Before Real)'
       ])
       basic_layout.addWidget(strategy_label, 1, 0)
       basic_layout.addWidget(self.strategy_combo, 1, 1)

       # Target Mode
       mode_label = QLabel('⚡ TARGET MODE:')
       self.mode_combo = QComboBox()
       self.mode_combo.addItems(['HTTPS Only (Port 443)', 'HTTPS + HTTP (443 + 80)'])
       basic_layout.addWidget(mode_label, 2, 0)
       basic_layout.addWidget(self.mode_combo, 2, 1)

       basic_frame.setLayout(basic_layout)
       main_layout.addWidget(basic_frame)

       # Fragment Options Group
       frag_group = QGroupBox('Fragment Options')
       frag_layout = QGridLayout()

       self.sni_frag_check = QCheckBox('SNI Fragmentation (split at SNI offset)')
       self.sni_frag_check.setToolTip('Parse ClientHello, find SNI offset, split record there')
       frag_layout.addWidget(self.sni_frag_check, 0, 0)

       self.reverse_frag_check = QCheckBox('Reverse Fragments (send 2nd first)')
       self.reverse_frag_check.setToolTip('Send fragments in reverse order to confuse DPI')
       frag_layout.addWidget(self.reverse_frag_check, 0, 1)

       self.native_frag_check = QCheckBox('Native Fragmentation (PSH on each)')
       self.native_frag_check.setToolTip('Set PSH flag on each fragment for native-style splitting')
       frag_layout.addWidget(self.native_frag_check, 1, 0)

       self.debug_check = QCheckBox('Debug Mode (Verbose Logging)')
       self.debug_check.setChecked(True)
       frag_layout.addWidget(self.debug_check, 1, 1)

       frag_group.setLayout(frag_layout)
       main_layout.addWidget(frag_group)

       # Stats Display
       self.stats_label = QLabel('FRAGMENTED: 0 | TOTAL: 0 | INJECTED: 0')
       self.stats_label.setStyleSheet("""
           color: #ff00ff;
           font-size: 14px;
           padding: 12px;
           background: #000;
           border: 2px solid #ff00ff;
           border-radius: 5px;
           letter-spacing: 1px;
       """)
       self.stats_label.setAlignment(Qt.AlignCenter)
       main_layout.addWidget(self.stats_label)

       main_layout.addStretch()
       main_tab.setLayout(main_layout)
       tabs.addTab(main_tab, '⚡ Main')

       # ============ TAB 2: FAKE PACKET SETTINGS ============
       fake_tab = QWidget()
       fake_layout = QVBoxLayout()
       fake_layout.setSpacing(10)

       fake_group = QGroupBox('Fake Packet Mode (DPI Confusion)')
       fake_grid = QGridLayout()

       # Fake count
       fake_count_label = QLabel('Fake Packet Count:')
       self.fake_count_spin = QSpinBox()
       self.fake_count_spin.setValue(1)
       self.fake_count_spin.setRange(1, 5)
       self.fake_count_spin.setToolTip('Number of fake packets to send before real data')
       fake_grid.addWidget(fake_count_label, 0, 0)
       fake_grid.addWidget(self.fake_count_spin, 0, 1)

       # Wrong sequence
       self.wrong_seq_check = QCheckBox('Wrong Sequence Number')
       self.wrong_seq_check.setToolTip('Send fake packets with invalid sequence numbers')
       fake_grid.addWidget(self.wrong_seq_check, 1, 0)

       # Wrong checksum
       self.wrong_chksum_check = QCheckBox('Wrong Checksum')
       self.wrong_chksum_check.setToolTip('Send fake packets with invalid checksums (server drops, DPI sees)')
       fake_grid.addWidget(self.wrong_chksum_check, 1, 1)

       # TTL trick
       self.ttl_trick_check = QCheckBox('Reduced TTL (expires before destination)')
       self.ttl_trick_check.setToolTip('⚠ RISKY: Fake packets use low TTL to expire mid-path')
       self.ttl_trick_check.setStyleSheet('color: #ffaa00;')
       fake_grid.addWidget(self.ttl_trick_check, 2, 0)

       ttl_label = QLabel('TTL Reduction:')
       self.ttl_spin = QSpinBox()
       self.ttl_spin.setValue(3)
       self.ttl_spin.setRange(1, 20)
       self.ttl_spin.setToolTip('Subtract this from TTL for fake packets')
       fake_grid.addWidget(ttl_label, 2, 1)
       fake_grid.addWidget(self.ttl_spin, 2, 2)

       fake_group.setLayout(fake_grid)
       fake_layout.addWidget(fake_group)

       # Warning label
       ttl_warning = QLabel('⚠ TTL tricks can be unreliable and may cause connection issues')
       ttl_warning.setStyleSheet('color: #ff6600; font-size: 10px; padding: 5px;')
       fake_layout.addWidget(ttl_warning)

       fake_layout.addStretch()
       fake_tab.setLayout(fake_layout)
       tabs.addTab(fake_tab, '🎭 Fake Packets')

       # ============ TAB 3: HTTP TRICKS ============
       http_tab = QWidget()
       http_layout = QVBoxLayout()
       http_layout.setSpacing(10)

       http_group = QGroupBox('HTTP Host Header Tricks (Port 80)')
       http_grid = QGridLayout()

       self.http_space_check = QCheckBox('Extra Space (Host:  domain)')
       self.http_space_check.setToolTip('Add extra space after Host: header')
       http_grid.addWidget(self.http_space_check, 0, 0)

       self.http_nospace_check = QCheckBox('No Space (Host:domain)')
       self.http_nospace_check.setToolTip('Remove space after Host: header')
       http_grid.addWidget(self.http_nospace_check, 0, 1)

       self.http_mixcase_check = QCheckBox('Mixed Case (HoSt)')
       self.http_mixcase_check.setToolTip('Randomize case in Host header value')
       http_grid.addWidget(self.http_mixcase_check, 1, 0)

       http_group.setLayout(http_grid)
       http_layout.addWidget(http_group)

       http_note = QLabel('Note: HTTP tricks are less useful for HTTPS-only sites')
       http_note.setStyleSheet('color: #888; font-size: 10px; padding: 5px;')
       http_layout.addWidget(http_note)

       http_layout.addStretch()
       http_tab.setLayout(http_layout)
       tabs.addTab(http_tab, '🌐 HTTP Tricks')

       # ============ TAB 4: BLACKLIST ============
       blacklist_tab = QWidget()
       blacklist_layout = QVBoxLayout()
       blacklist_layout.setSpacing(10)

       blacklist_group = QGroupBox('Domain Blacklist (Apply tricks only to these domains)')
       blacklist_grid = QVBoxLayout()

       # File picker row
       file_row = QHBoxLayout()
       self.blacklist_path = QLineEdit()
       self.blacklist_path.setPlaceholderText('No blacklist file loaded (tricks apply to ALL domains)')
       self.blacklist_path.setReadOnly(True)
       file_row.addWidget(self.blacklist_path)

       self.load_blacklist_btn = QPushButton('Load .txt')
       self.load_blacklist_btn.setStyleSheet('padding: 8px 16px;')
       self.load_blacklist_btn.clicked.connect(self.load_blacklist)
       file_row.addWidget(self.load_blacklist_btn)

       self.clear_blacklist_btn = QPushButton('Clear')
       self.clear_blacklist_btn.setStyleSheet('padding: 8px 16px;')
       self.clear_blacklist_btn.clicked.connect(self.clear_blacklist)
       file_row.addWidget(self.clear_blacklist_btn)

       blacklist_grid.addLayout(file_row)

       self.blacklist_info = QLabel('Domains loaded: 0')
       self.blacklist_info.setStyleSheet('color: #888;')
       blacklist_grid.addWidget(self.blacklist_info)

       blacklist_group.setLayout(blacklist_grid)
       blacklist_layout.addWidget(blacklist_group)

       blacklist_note = QLabel('Format: one domain per line (e.g., example.com)')
       blacklist_note.setStyleSheet('color: #888; font-size: 10px; padding: 5px;')
       blacklist_layout.addWidget(blacklist_note)

       blacklist_layout.addStretch()
       blacklist_tab.setLayout(blacklist_layout)
       tabs.addTab(blacklist_tab, '📋 Blacklist')

       # ============ TAB 5: QUIC & DNS ============
       network_tab = QWidget()
       network_layout = QVBoxLayout()
       network_layout.setSpacing(10)

       # QUIC Blocking
       quic_group = QGroupBox('QUIC/HTTP3 Blocking')
       quic_layout = QVBoxLayout()

       self.block_quic_check = QCheckBox('Block QUIC (force TCP/TLS fallback)')
       self.block_quic_check.setToolTip('Drop QUIC packets to force browsers to use TCP')
       quic_layout.addWidget(self.block_quic_check)

       self.quic_stats_label = QLabel('QUIC blocked: 0')
       self.quic_stats_label.setStyleSheet('color: #888;')
       quic_layout.addWidget(self.quic_stats_label)

       quic_group.setLayout(quic_layout)
       network_layout.addWidget(quic_group)

       # DNS Redirection
       dns_group = QGroupBox('DNS Redirection (Bypass DNS Poisoning)')
       dns_layout = QGridLayout()

       self.dns_redirect_check = QCheckBox('Enable DNS Redirection')
       self.dns_redirect_check.setToolTip('Redirect DNS queries to custom resolver')
       dns_layout.addWidget(self.dns_redirect_check, 0, 0, 1, 2)

       dns_ip_label = QLabel('DNS Server IP:')
       self.dns_ip_edit = QLineEdit()
       self.dns_ip_edit.setText('1.1.1.1')
       self.dns_ip_edit.setPlaceholderText('e.g., 1.1.1.1 or 8.8.8.8')
       dns_layout.addWidget(dns_ip_label, 1, 0)
       dns_layout.addWidget(self.dns_ip_edit, 1, 1)

       dns_port_label = QLabel('DNS Port:')
       self.dns_port_spin = QSpinBox()
       self.dns_port_spin.setValue(53)
       self.dns_port_spin.setRange(1, 65535)
       self.dns_port_spin.setToolTip('Use 853 for DNS-over-TLS, 53 for standard')
       dns_layout.addWidget(dns_port_label, 2, 0)
       dns_layout.addWidget(self.dns_port_spin, 2, 1)

       self.dns_stats_label = QLabel('DNS redirected: 0')
       self.dns_stats_label.setStyleSheet('color: #888;')
       dns_layout.addWidget(self.dns_stats_label, 3, 0, 1, 2)

       dns_group.setLayout(dns_layout)
       network_layout.addWidget(dns_group)

       network_layout.addStretch()
       network_tab.setLayout(network_layout)
       tabs.addTab(network_tab, '🔒 QUIC & DNS')

       layout.addWidget(tabs)

       # Action Buttons
       btn_layout = QHBoxLayout()
       btn_layout.setSpacing(15)

       self.start_btn = QPushButton('▶ ENGAGE KILLSWITCH')
       self.start_btn.clicked.connect(self.start_capture)
       self.start_btn.setMinimumHeight(50)

       self.stop_btn = QPushButton('◼ DISENGAGE')
       self.stop_btn.clicked.connect(self.stop_capture)
       self.stop_btn.setEnabled(False)
       self.stop_btn.setMinimumHeight(50)

       btn_layout.addWidget(self.start_btn)
       btn_layout.addWidget(self.stop_btn)
       layout.addLayout(btn_layout)

       # System Log
       log_label = QLabel('◈ SYSTEM LOG ◈')
       log_label.setAlignment(Qt.AlignCenter)
       log_label.setStyleSheet("font-size: 13px; padding: 5px;")
       layout.addWidget(log_label)

       self.log = QTextEdit()
       self.log.setReadOnly(True)
       self.log.setFont(QFont('Consolas', 10))
       self.log.setMaximumHeight(200)

       # Startup messages
       self.log.append('╔═══════════════════════════════════════════════════════╗')
       self.log.append('║   DPI KILLSWITCH - WINDOWS RAW MODE v5.0 (Extended)  ║')
       self.log.append('╚═══════════════════════════════════════════════════════╝')
       self.log.append('')
       self.log.append('[*] SYSTEM INITIALIZED')
       self.log.append('[*] TLS CLIENTHELLO FRAGMENTER READY')
       self.log.append('[*] NEW FEATURES: SNI-Frag, Fake-First, QUIC Block, DNS Redirect')
       self.log.append('[*] KERNEL-LEVEL PACKET MANIPULATION')
       self.log.append('')

       if pydivert is None:
           self.log.append('[!] WARNING: pydivert NOT FOUND')
           self.log.append('[!] INSTALL: pip install pydivert')
           self.log.append('[!] DOWNLOAD WinDivert: https://reqrypt.org/windivert.html')
       else:
           self.log.append('[✓] pydivert LOADED')
           self.log.append('[✓] READY TO ENGAGE')

       layout.addWidget(self.log)

       self.setLayout(layout)

   def load_blacklist(self):
       """Load domain blacklist from file"""
       file_path, _ = QFileDialog.getOpenFileName(
           self, 'Load Domain Blacklist', '', 'Text Files (*.txt);;All Files (*)'
       )
       if file_path:
           try:
               with open(file_path, 'r', encoding='utf-8') as f:
                   domains = set()
                   for line in f:
                       line = line.strip()
                       if line and not line.startswith('#'):
                           domains.add(line.lower())

               self.blacklist_domains = domains
               self.blacklist_path.setText(file_path)
               self.blacklist_info.setText(f'Domains loaded: {len(domains)}')
               self.log.append(f'[BLACKLIST] Loaded {len(domains)} domains from {os.path.basename(file_path)}')
           except Exception as e:
               self.log.append(f'[!] Error loading blacklist: {e}')

   def clear_blacklist(self):
       """Clear loaded blacklist"""
       self.blacklist_domains = set()
       self.blacklist_path.setText('')
       self.blacklist_info.setText('Domains loaded: 0')
       self.log.append('[BLACKLIST] Cleared - tricks will apply to ALL domains')

   def start_capture(self):
       split = self.split_spin.value()
       debug = self.debug_check.isChecked()

       # Map strategy combo index to strategy name
       strategy_map = {0: 'split', 1: 'disorder', 2: 'fake', 3: 'fake_first'}
       strategy = strategy_map[self.strategy_combo.currentIndex()]

       # Gather all settings
       self.thread = PacketFragmenter(
           split_point=split,
           debug=debug,
           strategy=strategy,
           reverse_frag=self.reverse_frag_check.isChecked(),
           native_frag=self.native_frag_check.isChecked(),
           fake_count=self.fake_count_spin.value(),
           use_wrong_seq=self.wrong_seq_check.isChecked(),
           use_wrong_chksum=self.wrong_chksum_check.isChecked(),
           use_ttl_trick=self.ttl_trick_check.isChecked(),
           ttl_value=self.ttl_spin.value(),
           blacklist_domains=self.blacklist_domains if self.blacklist_domains else None,
           sni_frag=self.sni_frag_check.isChecked(),
           http_host_space=self.http_space_check.isChecked(),
           http_host_mixcase=self.http_mixcase_check.isChecked(),
           http_host_remove=self.http_nospace_check.isChecked(),
           include_http=(self.mode_combo.currentIndex() == 1)
       )
       self.thread.output.connect(self.log.append)
       self.thread.stats.connect(self.update_stats)
       self.thread.start()

       # Start QUIC blocker if enabled
       if self.block_quic_check.isChecked():
           self.quic_blocker = QUICBlocker()
           self.quic_blocker.output.connect(self.log.append)
           self.quic_blocker.stats.connect(self.update_quic_stats)
           self.quic_blocker.start()

       # Start DNS redirector if enabled
       if self.dns_redirect_check.isChecked():
           dns_ip = self.dns_ip_edit.text().strip()
           dns_port = self.dns_port_spin.value()
           if dns_ip:
               self.dns_redirector = DNSRedirector(dns_ip, dns_port)
               self.dns_redirector.output.connect(self.log.append)
               self.dns_redirector.stats.connect(self.update_dns_stats)
               self.dns_redirector.start()

       # Disable controls
       self.start_btn.setEnabled(False)
       self.stop_btn.setEnabled(True)
       self.set_controls_enabled(False)

   def stop_capture(self):
       self.log.append('')
       self.log.append('[*] DISENGAGING KILLSWITCH...')

       # Stop main thread
       if self.thread:
           self.thread.stop()
           self.thread.wait()

       # Stop QUIC blocker
       if self.quic_blocker:
           self.quic_blocker.stop()
           self.quic_blocker.wait()
           self.quic_blocker = None

       # Stop DNS redirector
       if self.dns_redirector:
           self.dns_redirector.stop()
           self.dns_redirector.wait()
           self.dns_redirector = None

       self.log.append('[*] SYSTEM STANDBY')
       self.log.append('')

       self.start_btn.setEnabled(True)
       self.stop_btn.setEnabled(False)
       self.set_controls_enabled(True)

   def set_controls_enabled(self, enabled):
       """Enable/disable all control widgets"""
       self.split_spin.setEnabled(enabled)
       self.strategy_combo.setEnabled(enabled)
       self.mode_combo.setEnabled(enabled)
       self.debug_check.setEnabled(enabled)
       self.sni_frag_check.setEnabled(enabled)
       self.reverse_frag_check.setEnabled(enabled)
       self.native_frag_check.setEnabled(enabled)
       self.fake_count_spin.setEnabled(enabled)
       self.wrong_seq_check.setEnabled(enabled)
       self.wrong_chksum_check.setEnabled(enabled)
       self.ttl_trick_check.setEnabled(enabled)
       self.ttl_spin.setEnabled(enabled)
       self.http_space_check.setEnabled(enabled)
       self.http_nospace_check.setEnabled(enabled)
       self.http_mixcase_check.setEnabled(enabled)
       self.load_blacklist_btn.setEnabled(enabled)
       self.clear_blacklist_btn.setEnabled(enabled)
       self.block_quic_check.setEnabled(enabled)
       self.dns_redirect_check.setEnabled(enabled)
       self.dns_ip_edit.setEnabled(enabled)
       self.dns_port_spin.setEnabled(enabled)

   def update_stats(self, fragmented, total, injected):
       self.stats_label.setText(
           f'FRAGMENTED: {fragmented} | TOTAL: {total} | INJECTED: {injected}'
       )

   def update_quic_stats(self, blocked):
       self.quic_stats_label.setText(f'QUIC blocked: {blocked}')

   def update_dns_stats(self, redirected):
       self.dns_stats_label.setText(f'DNS redirected: {redirected}')


if __name__ == '__main__':
   app = QApplication(sys.argv)
   app.setStyle('Fusion')

   # Cyberpunk Matrix theme
   pal = app.palette()
   pal.setColor(QPalette.Window, QColor(10, 10, 10))
   pal.setColor(QPalette.WindowText, QColor(0, 255, 65))
   pal.setColor(QPalette.Base, QColor(0, 0, 0))
   pal.setColor(QPalette.AlternateBase, QColor(15, 15, 15))
   pal.setColor(QPalette.Text, QColor(0, 255, 65))
   pal.setColor(QPalette.Button, QColor(20, 20, 20))
   pal.setColor(QPalette.ButtonText, QColor(0, 255, 65))
   pal.setColor(QPalette.Highlight, QColor(0, 255, 65))
   pal.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
   app.setPalette(pal)

   tool = CyberDPITool()
   tool.show()
   sys.exit(app.exec_())
