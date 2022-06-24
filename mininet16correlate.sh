#!/bin/bash


# the path to the behavioal goes here
SW_Path="../../behavioral-model-main/targets/simple_switch/simple_switch_CLI"

sudo mn -c

#added a sleep 5 seconds to wait for the switches to boot up, depends on the system performance
gnome-terminal --tab -- bash -c "sleep 5; python3 $SW_Path --thrift-port 9090 < ./commands/mininet_sum_fs/switch0.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $SW_Path --thrift-port 9091 < ./commands/mininet_sum_fs/switch1.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $SW_Path --thrift-port 9092 < ./commands/mininet_sum_fs/switch2.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $SW_Path --thrift-port 9093 < ./commands/mininet_sum_fs/switch3.txt"

# start the relevant mininet
sudo python ./mininet/mynet.py --json-collector './switches/collector16correlate/switch.json' --json-netswitch './switches/netswitch_fs/switch.json'
