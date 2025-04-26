#!/usr/bin/env python3.12
import time
import subprocess


def ping_ip(ip):
    start_time = time.time()
    try:
        response = subprocess.run(
            ["ping", "-c", "1", ip], capture_output=True, text=True
        )
        end_time = time.time()
        if response.returncode == 0:
            return f"{ip}=>{int((end_time - start_time)*1000)}"
        else:
            return f"{ip}:failed"
    except Exception as e:
        return f"Error pinging {ip}: {e}"


def main():
    ips = ["94.140.14.15", "8.8.8.8", "1.1.1.1", "9.9.9.9"]
    while True:
        ping_results = [ping_ip(ip) for ip in ips]
        print(time.strftime('%Y-%m-%d %H:%M:%S'), " | ".join(ping_results))
        time.sleep(10)


if __name__ == "__main__":
    main()
