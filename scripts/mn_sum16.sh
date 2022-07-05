#!/bin/bash


# import globalb variables that are shard by multiple scripts
source ./vars.sh

# get path to this sh file and change to it's directory so it can be called
# from any folder.
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}";
cd "$( dirname -- "$SCRIPT_PATH"; )";

# path to the network and collector siwtches
PATH_NETSW="$PATH_SW/net/sw_fs/switch.json"
PATH_COLLECTOR="$PATH_SW/collector/sum16/switch.json"


# clear the mininet cash
sudo mn -c

# commands for installing the flow rules to the switches.
# added a sleep 5 seconds to wait for the switches to boot up, varies with
# system performance
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9090 < ../commands/mininet_sum_fs/switch0.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9091 < ../commands/mininet_sum_fs/switch1.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9092 < ../commands/mininet_sum_fs/switch2.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9093 < ../commands/mininet_sum_fs/switch3.txt"

# start the relevant mininet
sudo python ../mininet/mynet.py --behavioral-exe "$PATH_BEHAVIORAL" --json-collector "$PATH_COLLECTOR" --json-netswitch "$PATH_NETSW"
