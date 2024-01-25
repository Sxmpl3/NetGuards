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

from scapy.all import sniff, IP, ICMP, ARP
from collections import defaultdict
import threading
import time

class DoSGuard:
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
                        print(f"[!] Sospecha de ataque DDoS desde {source_ip} (Paquetes: {count})")

    def start_analysis(self):
        sniff(prn=self.packet_callback, store=0)

    def set_target_ip(self, new_target_ip):
        self.target_ip = new_target_ip

class DDoSGuard:
    def __init__(self, target_ip, threshold=10, block_duration=60):
        self.target_ip = target_ip
        self.threshold = threshold
        self.block_duration = block_duration
        self.packet_counter = defaultdict(int)
        self.blocked_ips = set()
        self.lock = threading.Lock()

    def packet_callback(self, packet):
        if IP in packet and ICMP in packet:
            source_ip = packet[IP].src
            if source_ip == self.target_ip:
                with self.lock:
                    if source_ip not in self.blocked_ips:
                        self.packet_counter[source_ip] += 1
                        count = self.packet_counter[source_ip]
                        if count > self.threshold:
                            print(f"[!] Suspected DDoS attack from {source_ip}. Blocking for {self.block_duration} seconds.")
                            self.blocked_ips.add(source_ip)
                            threading.Timer(self.block_duration, self.unblock_ip, args=(source_ip,)).start()

    def unblock_ip(self, ip):
        with self.lock:
            if ip in self.blocked_ips:
                print(f"[+] IP {ip} unblocked.")
                self.blocked_ips.remove(ip)

    def start_analysis(self):
        sniff(prn=self.packet_callback, store=0)

    def set_target_ip(self, new_target_ip):
        self.target_ip = new_target_ip

class ArpGuard:
    def __init__(self, target_ip, threshold=5):
        self.target_ip = target_ip
        self.threshold = threshold
        self.arp_counter = defaultdict(int)
        self.lock = threading.Lock()

    def arp_callback(self, packet):
        if ARP in packet:
            sender_ip = packet[ARP].psrc
            if sender_ip == self.target_ip:
                with self.lock:
                    self.arp_counter[sender_ip] += 1
                    count = self.arp_counter[sender_ip]
                    if count > self.threshold:
                        print(f"[!] Sospecha de ARP Spoofing desde {sender_ip} (Paquetes: {count})")

    def start_analysis(self):
        sniff(prn=self.arp_callback, filter="arp", store=0)

    def set_target_ip(self, new_target_ip):
        self.target_ip = new_target_ip
