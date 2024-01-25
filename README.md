# NetGuards

NetGuard is a Python library designed for network traffic analysis and detection of suspicious patterns. It provides a simple yet effective way to monitor network traffic and identify potential threats, such as denial-of-service (DoS) attacks.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install NetGuard.

```pip install NetGuard```


# Usage
# Quick Start

```
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
```

# Features

- Dynamic Target IP: Change the target IP dynamically during runtime.
- Denial-of-Service (DoS) Detection: Monitor and detect potential DoS attacks based on packet frequency.
  
# Contributing

- Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
  
# License

- [MIT](https://opensource.org/licenses/MIT)
