#!/bin/bash

# import globalb variables that are shard by multiple scripts
source ./vars.sh

# get path to this sh file and change to it's directory so it can be called
# from any folder.
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}";
cd "$( dirname -- "$SCRIPT_PATH"; )";

# path to the network and collector siwtches
PATH_NETSW="$PATH_SW/net/sw0/switch.json"
PATH_COLLECTOR="$PATH_SW/collector/nrmfwd/switch.json"

# clear the mininet cash
sudo mn -c

# commands for installing the flow rules to the switches.
# added a sleep 5 seconds to wait for the switches to boot up before installing
# the flow rules, varies with system performance.
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9090 < ../commands/mininet01/switch0.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9091 < ../commands/mininet01/switch1.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9092 < ../commands/mininet01/switch2.txt"
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9093 < ../commands/mininet01/switch3.txt"


# start the mininet with the relevant arguments
sudo python ../mininet/mynet.py --behavioral-exe "$PATH_BEHAVIORAL" --json-collector "$PATH_COLLECTOR" --json-netswitch "$PATH_NETSW"
