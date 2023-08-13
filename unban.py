import re
import subprocess
import time
from collections import deque, defaultdict
from datetime import datetime, timedelta

def ban(ip_address):
    command = f"iptables -A INPUT -s {ip_address} -j DROP"
    subprocess.run(command, shell=True)

def unban(ip_address):
    command = f"iptables -D INPUT -s {ip_address} -j DROP"
    subprocess.run(command, shell=True)


log_file_path = "/var/log/auth.log"
threshold = 2  # 실패한 시도 임계치
limit_time = timedelta(seconds=60)  # 1분 동안 시도되면 block
banning_time = timedelta(seconds=5) # 5분 지나면 풀림

ip_address_failed_attempts = {}
log_queue = defaultdict(lambda: deque())

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
                ip_address = match.group(1)
                # check repeat
                repeat_count = 1
                rematch = re.search(r"message repeated (\d+) times", line)
                if rematch:
                    repeat_count = int(rematch.group(1))

                # store log time
                dmatch = re.search(r"(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})", line)
                if dmatch:
                    log_time = dmatch.group(1)
                    log_queue[ip_address].append(datetime.strptime(log_time, "%b %d %H:%M:%S"))

                print(log_time)


                if ip_address in ip_address_failed_attempts:
                    # print("total fail: ", ip_address_failed_attempts[ip_address])

                    ip_address_failed_attempts[ip_address] += repeat_count
                else:
                    # print("total fail: ", ip_address_failed_attempts[ip_address])

                    ip_address_failed_attempts[ip_address] = repeat_count

                print("Failed password, repeat:",repeat_count)

                if ip_address_failed_attempts[ip_address] >= threshold:
                    now = datetime.now().strftime('%b %d %H:%M:%S')
                    
                    timediff = datetime.strptime(now, '%b %d %H:%M:%S') - log_queue[ip_address][0]

                    if timediff > limit_time:
                        print("over time")
                        q_len = len(log_queue[ip_address])-1
                        for i in range(q_len-1):
                            if datetime.strptime(now, '%b %d %H:%M:%S')-log_queue[ip_address][i]:
                                log_queue[ip_address].popleft()
                                ip_address_failed_attempts[ip_address] -= 1
                            else: break
                        
                        continue

                    else:
                        ban(ip_address)
                        ban_time = datetime.now()
                        print(f"Blocked {ip_address} after {threshold} failed attempts.")
                        print("ban time:", ban_time)

                        while datetime.now()-ban_time<=banning_time:
                            continue

                        print("unban time: ", datetime.now())
                        unban(ip_address)
                        print(f"Un Blocked {ip_address}.")
                        ip_address_failed_attempts[ip_address] = 0  # 차단 후 카운트 초기화
                        