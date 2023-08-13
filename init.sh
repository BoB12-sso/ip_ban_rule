#!/bin/bash

sudo truncate -s 0 /var/log/auth.log
iptables -A INPUT -s {attacker ip} -j ACCEPT
iptables -F
