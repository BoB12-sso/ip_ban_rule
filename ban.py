import re
import subprocess
import time

def ban(ip_address):
    command = f"iptables -A INPUT -s {ip_address} -j DROP"
    subprocess.run(command, shell=True)

log_file_path = "/var/log/auth.log"
threshold = 5  # 5번 넘으면 차단

ip_address_failed_attempts = {}

with open(log_file_path, "r") as log_file:
    print("start monitoring..")
    while True:
        line = log_file.readline()
        if not line:
            time.sleep(1)  # 파일의 끝까지 도달했을 때 대기 후 다시 검사
            continue

        if "Failed password" in line:
            match = re.search(r"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)

            if match:
                repeat_count = 1
                
                #반복 여부 검사
                rematch = re.search(r"message repeated (\d+) times",line)

                if rematch:
                    repeat_count = int(rematch.group(1))

                print("Failed password: ",repeat_count)
                ip_address = match.group(1)
                if ip_address in ip_address_failed_attempts:
                    ip_address_failed_attempts[ip_address] += repeat_count
                else:
                    ip_address_failed_attempts[ip_address] = repeat_count

                if ip_address_failed_attempts[ip_address] >= threshold:
                    ban(ip_address)
                    print(f"Blocked {ip_address} after {threshold} failed attempts.")
                    ip_address_failed_attempts[ip_address] = 0  # 차단 후 카운트 초기화
                    break
