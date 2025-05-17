#!/usr/bin/env python3.12
import time
import subprocess


def ping_ip(ip):
    start_time = time.time()
    timeout = 1
    try:
        response = subprocess.run(["ping", "-c", str(timeout), ip], capture_output=True, text=False)
        end_time = time.time()
        if response.returncode == 0:
            return end_time - start_time
        else:
            return timeout
    except Exception as e:
        return f"Error pinging {ip}: {e}"


def main():
    dns_servers_list = ["94.140.14.15", "8.8.8.8", "1.1.1.1", "9.9.9.9"]
    results = {}
    for each in dns_servers_list:
        results[each] = []
    for i in range(60-1):
        for ip in dns_servers_list:
            results[ip].append(ping_ip(ip))
            print(f"Counter:{i} Delay:{ping_ip(ip)} IP:{ip}")
        time.sleep(1)
    for key, value in results.items():
        print(f"IP:{key} has average delay of {round(sum(value)/len(value), 3)} sec")


if __name__ == "__main__":
    main()
