from NetGuard import DoSGuard, DDoSGuard, ArpGuard
import threading
import time

def dos_analysis():
    target_ip = "192.168.1.1"
    dos_guard = DoSGuard(target_ip=target_ip, threshold=10)
    dos_thread = threading.Thread(target=dos_guard.start_analysis)

    try:
        dos_thread.start()

        while True:
            new_target_ip = input("[>] Enter the new target IP (or press Enter to keep the current): ")
            if new_target_ip:
                dos_guard.set_target_ip(new_target_ip)
                print(f"[+] Target updated to: {new_target_ip}")

            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] DoS analysis stopped.")

def ddos_analysis():
    target_ip = "192.168.1.1"
    ddos_guard = DDoSGuard(target_ip=target_ip, threshold=10, block_duration=60)
    ddos_thread = threading.Thread(target=ddos_guard.start_analysis)

    try:
        ddos_thread.start()

        while True:
            new_target_ip = input("[>] Enter the new target IP (or press Enter to keep the current): ")
            if new_target_ip:
                ddos_guard.set_target_ip(new_target_ip)
                print(f"[+] Target updated to: {new_target_ip}")

            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] DDoS analysis stopped.")

def arp_analysis():
    target_ip = "192.168.1.1"
    arp_guard = ArpGuard(target_ip=target_ip, threshold=5)
    arp_thread = threading.Thread(target=arp_guard.start_analysis)

    try:
        arp_thread.start()

        while True:
            new_target_ip = input("[>] Enter the new target IP (or press Enter to keep the current): ")
            if new_target_ip:
                arp_guard.set_target_ip(new_target_ip)
                print(f"[+] Target updated to: {new_target_ip}")

            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] ARP analysis stopped.")

if __name__ == "__main__":
    dos_thread = threading.Thread(target=dos_analysis)
    ddos_thread = threading.Thread(target=ddos_analysis)
    arp_thread = threading.Thread(target=arp_analysis)

    dos_thread.start()
    ddos_thread.start()
    arp_thread.start()

    dos_thread.join()
    ddos_thread.join()
    arp_thread.join()
