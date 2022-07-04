#!/bin/bash
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}";

cd "$( dirname -- "$SCRIPT_PATH"; )";
# the path to the behavioal goes here
PATH_CLI="../../../behavioral-model-main/targets/simple_switch/simple_switch_CLI"
PATH_BEHAVIORAL="../../../behavioral-model-main/targets/simple_switch/simple_switch"
PATH_NETSW="../switches/net/netswitch_01/switch.json"
PATH_COLLECTOR="../switches/collector/nrmfwd/switch.json"

sudo mn -c

#added a sleep 5 seconds to wait for the switches to boot up
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9090 < ../commands/mininet01/switch0.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9091 < ../commands/mininet01/switch1.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9092 < ../commands/mininet01/switch2.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9093 < ../commands/mininet01/switch3.txt"


#start the relevant mininet
sudo python ../mininet/mynet.py --json-collector "$PATH_COLLECTOR" --json-netswitch "$PATH_NETSW" --behavioral-exe "$PATH_BEHAVIORAL"
