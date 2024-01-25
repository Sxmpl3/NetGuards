"""
NetGuard - Network Traffic Analyzer Library

Developed by: Sxmpl3
Copyright (c) 2024 Sxmpl3. All rights reserved.

This library is free software: you can redistribute it and/or modify it
under the terms of the MIT License as published by the Open Source Initiative.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
MIT License for more details.

You should have received a copy of the MIT License along with this program.
If not, see <https://opensource.org/licenses/MIT>.
"""

from scapy.all import sniff, IP, ICMP
from collections import defaultdict
import threading
import time

class NetworkAnalyzer:
    def __init__(self, target_ip, threshold=10):
        self.target_ip = target_ip
        self.threshold = threshold
        self.packet_counter = defaultdict(int)
        self.lock = threading.Lock()

    def packet_callback(self, packet):
        if IP in packet and ICMP in packet:
            source_ip = packet[IP].src
            if source_ip == self.target_ip:
                with self.lock:
                    self.packet_counter[source_ip] += 1
                    count = self.packet_counter[source_ip]
                    if count > self.threshold:
                        print(f"[!] Sospecha de ataque DoS desde {source_ip} (Paquetes: {count})")

    def start_analysis(self):
        sniff(prn=self.packet_callback, store=0)

    def set_target_ip(self, new_target_ip):
        self.target_ip = new_target_ip

if __name__ == "__main__":
    initial_target_ip = "192.168.1.1"
    analyzer = NetworkAnalyzer(target_ip=initial_target_ip, threshold=10)
    analysis_thread = threading.Thread(target=analyzer.start_analysis)
    
    try:
        analysis_thread.start()

        while True:
            new_target_ip = input("[>] Ingrese la nueva IP de destino (o presione Enter para mantener la actual): ")
            if new_target_ip:
                analyzer.set_target_ip(new_target_ip)
                print(f"[+] Objetivo actualizado a: {new_target_ip}")

            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Análisis de red detenido.")