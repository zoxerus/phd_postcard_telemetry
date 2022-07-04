#!/bin/bash
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}";
cd "$( dirname -- "$SCRIPT_PATH"; )";

# the path to the behavioal goes here, the command should have no spaces!!!!!!!
PATH_CLI="../../../behavioral-model-main/targets/simple_switch/simple_switch_CLI"
PATH_BEHAVIORAL="../../../behavioral-model-main/targets/simple_switch/simple_switch"
PATH_NETSW="../switches/net/netswitch_fs_ipfix/switch.json"
PATH_COLLECTOR="../switches/collector/sum16_ipfix/switch.json"

sudo mn -c

#added a sleep 5 seconds to wait for the switches to boot up, depends on the system performance
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9090 < ../commands/mininet_sum_fs/switch0.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9091 < ../commands/mininet_sum_fs/switch1.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9092 < ../commands/mininet_sum_fs/switch2.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9093 < ../commands/mininet_sum_fs/switch3.txt"

# start the relevant mininet
sudo python ../mininet/mynet.py --json-collector "$PATH_COLLECTOR" --json-netswitch "$PATH_NETSW" --behavioral-exe "$PATH_BEHAVIORAL"
