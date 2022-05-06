#!/bin/bash

# the path to the behavioal goes here
SW_Path="../../behavioral-model-main/targets/simple_switch/simple_switch_CLI"


sudo mn -c

#added a sleep 5 seconds to wait for the switches to boot up
gnome-terminal --tab -- bash -c "sleep 5; python3 $SW_Path --thrift-port 9090 < ./commands/mininet01/switch0.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $SW_Path --thrift-port 9091 < ./commands/mininet01/switch1.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $SW_Path --thrift-port 9092 < ./commands/mininet01/switch2.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $SW_Path --thrift-port 9093 < ./commands/mininet01/switch3.txt"


#start the relevant mininet
sudo python ./mininet/mynet.py
