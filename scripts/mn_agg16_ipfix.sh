#!/bin/bash

# get path to this sh file and change to it's directory so it can be called
# from any folder.
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}";
cd "$( dirname -- "$SCRIPT_PATH"; )";


# import globalb variables that are shard by multiple scripts
source ./vars.sh



# path to the network and collector siwtches
PATH_NETSW="$PATH_SW/net/sw_fs_ipfix/switch.json"
PATH_COLLECTOR="$PATH_SW/collector/agg16_ipfix/switch.json"

# clear the mininet cash
sudo mn -c

echo "$PATH_BEHAVIORAL"

# commands for installing the flow rules to the switches.
# added a sleep 5 seconds to wait for the switches to boot up before installing
# the flow rules, varies with system performance.
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9090 < ../commands/mininet_sum_fs/switch0.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9091 < ../commands/mininet_sum_fs/switch1.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9092 < ../commands/mininet_sum_fs/switch2.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9093 < ../commands/mininet_sum_fs/switch3.txt"

# start the relevant mininet
sudo python ../mininet/mynet.py --behavioral-exe "$PATH_BEHAVIORAL" --json-collector "$PATH_COLLECTOR" --json-netswitch "$PATH_NETSW"
