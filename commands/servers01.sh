#!/bin/bash

gnome-terminal --tab -- bash -c "python3 ./simple_switch_CLI --thrift-port 9090 < ./commands/servers01/switch0.txt; exec bash"
gnome-terminal --tab -- bash -c "python3 ./simple_switch_CLI --thrift-port 9091 < ./commands/servers01/switch1.txt; exec bash"
gnome-terminal --tab -- bash -c "python3 ./simple_switch_CLI --thrift-port 9092 < ./commands/servers01/switch2.txt; exec bash"
gnome-terminal --tab -- bash -c "python3 ./simple_switch_CLI --thrift-port 9093 < ./commands/servers01/switch3.txt; exec bash"
gnome-terminal --tab -- bash -c "python3 ./simple_switch_CLI --thrift-port 9094 < ./commands/servers01/switch4.txt; exec bash"

#printf \"\e]2;YOUR TITLE GOES HERE\a\"
