#!/bin/bash

gnome-terminal --tab -- bash -c "python3 ./simple_switch_CLI --thrift-port 9090 < ./commands/switch0.txt; exec bash"
gnome-terminal --tab -- bash -c "python3 ./simple_switch_CLI --thrift-port 9091 < ./commands/switch1.txt"
gnome-terminal --tab -- bash -c "python3 ./simple_switch_CLI --thrift-port 9092 < ./commands/switch2.txt"
gnome-terminal --tab -- bash -c "python3 ./simple_switch_CLI --thrift-port 9093 < ./commands/switch3.txt"
gnome-terminal --tab -- bash -c "python3 ./simple_switch_CLI --thrift-port 9094 < ./commands/switch4.txt"

#printf \"\e]2;YOUR TITLE GOES HERE\a\"
