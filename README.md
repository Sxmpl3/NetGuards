# NetGuard

NetGuard is a Python library designed for network traffic analysis and detection of suspicious patterns. It provides a simple yet effective way to monitor network traffic and identify potential threats, such as denial-of-service (DoS) attacks.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install NetGuard.

```pip install NetGuard```


# Usage
# Quick Start

```
from NetGuard.analyzer import NetworkAnalyzer

if __name__ == "__main__":
    # Initialize NetGuard analyzer with target IP and optional threshold
    analyzer = NetworkAnalyzer(target_ip="192.168.1.1", threshold=10)

    # Start network analysis in a separate thread
    analyzer_thread = threading.Thread(target=analyzer.start_analysis)
    analyzer_thread.start()

    # User input to dynamically change the target IP
    try:
        while True:
            new_target_ip = input("Enter the new target IP (or press Enter to keep the current one): ")
            if new_target_ip:
                analyzer.set_target_ip(new_target_ip)
                print(f"Target updated to: {new_target_ip}")

            time.sleep(1)
    except KeyboardInterrupt:
        print("Network analysis stopped.")
```

# Features

- Dynamic Target IP: Change the target IP dynamically during runtime.
- Denial-of-Service (DoS) Detection: Monitor and detect potential DoS attacks based on packet frequency.
  
# Contributing

- Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
  
# License

- [MIT](https://opensource.org/licenses/MIT)
