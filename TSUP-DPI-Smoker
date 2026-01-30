#!/usr/bin/env python3
"""
DPI KILLSWITCH - Windows Raw Packet Fragmenter
Requires: pydivert (WinDivert wrapper)
Run as Administrator: python dpi_killswitch.py
"""
import sys
import struct
import threading
from collections import defaultdict
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, 
                            QSpinBox, QLabel, QTextEdit, QHBoxLayout, QFrame, QComboBox)
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


class PacketFragmenter(QThread):
   output = Signal(str)
   stats = Signal(int, int, int)  # fragmented, total, injected
   
   def __init__(self, split_point, mode='outbound', debug=True, strategy='split'):
       super().__init__()
       self.split_point = split_point
       self.mode = mode
       self.running = True
       self.debug = debug
       self.strategy = strategy  # 'split', 'disorder', 'fake'
       
       # Stats
       self.packets_fragmented = 0
       self.packets_total = 0
       self.packets_injected = 0
       self.packets_passed = 0
       
       # Track connections to only fragment first ClientHello
       self.seen_connections = set()
       self.lock = threading.Lock()
       
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
   
   def fragment_payload(self, payload):
       """Pure TCP-level fragmentation for TLS ClientHello"""
       try:
           if not self.is_tls_client_hello(payload):
               return None
          
           # Need at least TLS header (5 bytes) + some data to split
           if len(payload) <= 5 + self.split_point:
               if self.debug:
                   self.output.emit(f'[DEBUG] Payload too small for split: {len(payload)} bytes (need > {5 + self.split_point})')
               return None
          
           # Split TCP payload: header + chunk1 | rest
           split_at = 5 + self.split_point
           first_frag = payload[:split_at]
           second_frag = payload[split_at:]
          
           if self.debug:
               self.output.emit(f'[DEBUG] TCP Frag ready: {len(first_frag)}B + {len(second_frag)}B (pure split)')
          
           return (first_frag, second_frag, b'')
          
       except Exception as e:
           self.output.emit(f'[!] FRAGMENT ERROR: {str(e)}')
           import traceback
           self.output.emit(f'[!] TRACE: {traceback.format_exc()[:300]}')
           return None
   def process_packet(self, w, packet):
       """Process packet with WinDivert"""
       try:
           self.packets_total += 1
           
           if self.debug and self.packets_total <= 5:
               self.output.emit(f'[DEBUG] Packet #{self.packets_total}: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}')
           
           # Only process TCP packets on port 443
           if not packet.tcp or packet.dst_port != 443:
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
           
           # Create connection identifier
           conn_id = (packet.src_addr, packet.dst_addr, packet.src_port, packet.dst_port)
           
           # Only fragment first ClientHello per connection
           with self.lock:
               if conn_id in self.seen_connections:
                   w.send(packet)
                   self.packets_passed += 1
                   return
           
           # Try to fragment
           result = self.fragment_payload(packet.payload)
           
           if result:
               first_frag, second_frag, _ = result
               
               with self.lock:
                   self.seen_connections.add(conn_id)
                   self.packets_fragmented += 1
               
               # Save original sequence number
               orig_seq = packet.tcp.seq_num
               
               if self.strategy == 'split':
                   # Standard split - send in order
                   packet.payload = first_frag
                   packet.tcp.psh = True
                   w.send(packet, recalculate_checksum=True)
                   
                   import time
                   time.sleep(0.001)  # 1ms delay
                   
                   packet.payload = second_frag
                   packet.tcp.seq_num = orig_seq + len(first_frag)
                   packet.tcp.psh = True
                   w.send(packet, recalculate_checksum=True)
                   
               elif self.strategy == 'disorder':
                   # Send SECOND fragment first (out of order)
                   packet.payload = second_frag
                   packet.tcp.seq_num = orig_seq + len(first_frag)
                   packet.tcp.psh = False
                   w.send(packet, recalculate_checksum=True)
                   
                   import time
                   time.sleep(0.002)  # 2ms delay
                   
                   # Then send first fragment
                   packet.payload = first_frag
                   packet.tcp.seq_num = orig_seq
                   packet.tcp.psh = True
                   w.send(packet, recalculate_checksum=True)
                   
               elif self.strategy == 'fake':
                   # Send fake SNI packet with wrong checksum (DPI sees it, server drops it)
                   fake_payload = first_frag[:40] + b'fake.example.com\x00\x00' + first_frag[60:]
                   if len(fake_payload) < len(first_frag):
                       fake_payload += b'\x00' * (len(first_frag) - len(fake_payload))
                   else:
                       fake_payload = fake_payload[:len(first_frag)]
                   
                   packet.payload = fake_payload
                   packet.tcp.psh = False
                   # Don't recalculate checksum - makes it invalid
                   w.send(packet, recalculate_checksum=False)
                   
                   import time
                   time.sleep(0.001)
                   
                   # Send real fragments
                   packet.payload = first_frag
                   packet.tcp.seq_num = orig_seq
                   packet.tcp.psh = True
                   w.send(packet, recalculate_checksum=True)
                   
                   packet.payload = second_frag
                   packet.tcp.seq_num = orig_seq + len(first_frag)
                   packet.tcp.psh = True
                   w.send(packet, recalculate_checksum=True)
               
               self.packets_injected += 2
               
               self.output.emit(
                   f'[>>] FRAGMENTED [{self.strategy.upper()}]: {packet.dst_addr}:{packet.dst_port} '
                   f'[{len(first_frag)}B + {len(second_frag)}B]'
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
           
           # WinDivert filter for outbound HTTPS traffic
           filter_str = "outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0"
           
           self.output.emit(f'[+] FILTER: {filter_str}')
           
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


class CyberDPITool(QWidget):
   def __init__(self):
       super().__init__()
       self.setWindowTitle('◈ DPI KILLSWITCH v4.20 - WINDOWS RAW MODE ◈')
       self.setGeometry(100, 100, 800, 700)
       self.setStyleSheet("""
           QWidget {
               background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                   stop:0 #0a0a0a, stop:1 #000000);
               color: #00ff41;
               font-family: 'Consolas', 'Courier New', monospace;
           }
           QPushButton {
               background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                   stop:0 #1a4d1a, stop:1 #0d260d);
               border: 2px solid #00ff41;
               border-radius: 8px;
               padding: 14px 28px;
               color: #00ff41;
               font-size: 14px;
               font-weight: bold;
               text-transform: uppercase;
               letter-spacing: 2px;
           }
           QPushButton:hover {
               background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                   stop:0 #2d7a2d, stop:1 #1a4d1a);
               border: 2px solid #00ffaa;
               color: #00ffaa;
           }
           QPushButton:pressed {
               background: #00ff41;
               color: #000;
           }
           QPushButton:disabled {
               background: #1a1a1a;
               border: 2px solid #333;
               color: #444;
           }
           QSpinBox {
               background: #0a0a0a;
               border: 2px solid #00ff41;
               border-radius: 5px;
               padding: 10px;
               color: #00ff41;
               font-size: 15px;
               font-weight: bold;
           }
           QSpinBox::up-button, QSpinBox::down-button {
               background: #1a4d1a;
               border: 1px solid #00ff41;
               width: 22px;
           }
           QSpinBox::up-button:hover, QSpinBox::down-button:hover {
               background: #00ff41;
           }
           QTextEdit {
               background: #000000;
               border: 2px solid #00ff41;
               border-radius: 8px;
               color: #00ff41;
               font-family: 'Consolas', monospace;
               font-size: 11px;
               padding: 12px;
               selection-background-color: #00ff41;
               selection-color: #000;
           }
           QLabel {
               color: #00ffaa;
               font-size: 12px;
               font-weight: bold;
           }
           QFrame {
               background: rgba(5, 5, 5, 200);
               border: 2px solid #00ff41;
               border-radius: 10px;
           }
           QComboBox {
               background: #0a0a0a;
               border: 2px solid #00ff41;
               border-radius: 5px;
               padding: 8px;
               color: #00ff41;
               font-weight: bold;
           }
           QComboBox::drop-down {
               border: none;
           }
           QComboBox QAbstractItemView {
               background: #0a0a0a;
               border: 2px solid #00ff41;
               color: #00ff41;
               selection-background-color: #00ff41;
               selection-color: #000;
           }
       """)
       
       layout = QVBoxLayout()
       layout.setSpacing(15)
       layout.setContentsMargins(20, 20, 20, 20)

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

       # Control Panel
       control_frame = QFrame()
       control_layout = QVBoxLayout()
       control_layout.setSpacing(15)
       control_layout.setContentsMargins(15, 15, 15, 15)

       # Split Point
       split_layout = QHBoxLayout()
       split_label = QLabel('⚡ FRAGMENT SIZE:')
       split_label.setStyleSheet("font-size: 13px;")
       self.split_spin = QSpinBox()
       self.split_spin.setValue(100)
       self.split_spin.setRange(40, 500)
       self.split_spin.setSuffix(' bytes')
       split_layout.addWidget(split_label)
       split_layout.addWidget(self.split_spin)
       split_layout.addStretch()
       control_layout.addLayout(split_layout)

       # Strategy Selection
       strategy_layout = QHBoxLayout()
       strategy_label = QLabel('⚡ BYPASS STRATEGY:')
       strategy_label.setStyleSheet("font-size: 13px;")
       self.strategy_combo = QComboBox()
       self.strategy_combo.addItems([
           'Split (Standard)',
           'Disorder (Out-of-Order)', 
           'Fake SNI (Decoy Packet)'
       ])
       self.strategy_combo.setToolTip(
           'Split: Normal fragmentation\n'
           'Disorder: Send fragments backwards\n'
           'Fake SNI: Send decoy packet first'
       )
       strategy_layout.addWidget(strategy_label)
       strategy_layout.addWidget(self.strategy_combo)
       strategy_layout.addStretch()
       control_layout.addLayout(strategy_layout)

       # Mode Selection (for future expansion)
       mode_layout = QHBoxLayout()
       mode_label = QLabel('⚡ TARGET MODE:')
       mode_label.setStyleSheet("font-size: 13px;")
       self.mode_combo = QComboBox()
       self.mode_combo.addItems(['HTTPS Only (Port 443)', 'All TLS Traffic', 'Custom Ports'])
       mode_layout.addWidget(mode_label)
       mode_layout.addWidget(self.mode_combo)
       mode_layout.addStretch()
       control_layout.addLayout(mode_layout)

       # Debug Mode Toggle
       debug_layout = QHBoxLayout()
       debug_label = QLabel('⚡ DEBUG MODE:')
       debug_label.setStyleSheet("font-size: 13px;")
       self.debug_check = QCheckBox('Enable Verbose Logging')
       self.debug_check.setChecked(True)
       self.debug_check.setStyleSheet("font-size: 12px;")
       debug_layout.addWidget(debug_label)
       debug_layout.addWidget(self.debug_check)
       debug_layout.addStretch()
       control_layout.addLayout(debug_layout)

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
       control_layout.addWidget(self.stats_label)

       control_frame.setLayout(control_layout)
       layout.addWidget(control_frame)

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
       
       # Startup messages
       self.log.append('╔═══════════════════════════════════════════════╗')
       self.log.append('║   DPI KILLSWITCH - WINDOWS RAW MODE v4.20    ║')
       self.log.append('╚═══════════════════════════════════════════════╝')
       self.log.append('')
       self.log.append('[*] SYSTEM INITIALIZED')
       self.log.append('[*] TLS CLIENTHELLO FRAGMENTER READY')
       self.log.append('[*] KERNEL-LEVEL PACKET MANIPULATION')
       self.log.append('[*] NO PROXY CONFIGURATION NEEDED')
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
       self.thread = None

   def start_capture(self):
       split = self.split_spin.value()
       debug = self.debug_check.isChecked()
       
       # Map strategy combo index to strategy name
       strategy_map = {0: 'split', 1: 'disorder', 2: 'fake'}
       strategy = strategy_map[self.strategy_combo.currentIndex()]
       
       self.thread = PacketFragmenter(split, debug=debug, strategy=strategy)
       self.thread.output.connect(self.log.append)
       self.thread.stats.connect(self.update_stats)
       self.thread.start()
       
       self.start_btn.setEnabled(False)
       self.stop_btn.setEnabled(True)
       self.split_spin.setEnabled(False)
       self.strategy_combo.setEnabled(False)
       self.mode_combo.setEnabled(False)
       self.debug_check.setEnabled(False)

   def stop_capture(self):
       if self.thread:
           self.log.append('')
           self.log.append('[*] DISENGAGING KILLSWITCH...')
           self.thread.stop()
           self.thread.wait()
           self.log.append('[*] SYSTEM STANDBY')
           self.log.append('')
           
           self.start_btn.setEnabled(True)
           self.stop_btn.setEnabled(False)
           self.split_spin.setEnabled(True)
           self.strategy_combo.setEnabled(True)
           self.mode_combo.setEnabled(True)
           self.debug_check.setEnabled(True)

   def update_stats(self, fragmented, total, injected):
       self.stats_label.setText(
           f'FRAGMENTED: {fragmented} | TOTAL: {total} | INJECTED: {injected}'
       )


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
