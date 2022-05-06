#!/bin/bash

# Copyright 2013-present Barefoot Networks, Inc. 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

#source $THIS_DIR/../../env.sh

#P4C_BM_SCRIPT=$P4C_BM_PATH/p4c_bm/__main__.py

#SWITCH_PATH=$BMV2_PATH/targets/simple_switch/simple_switch

#CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI

#Build switch entries file
#python write_entries_scan.py $1
#cat base.txt var.txt > entries.txt 

# Probably not very elegant but it works nice here: we enable interactive mode
# to be able to use fg. We start the switch in the background, sleep for 2
# minutes to give it time to start, then add the entries and put the switch
# process back in the foreground
set -m
#p4c-bmv2 register_scan.p4 --json register_scan.json
# This gets root permissions, and gives libtool the opportunity to "warm-up"
sudo ./behavioral-model/targets/simple_switch/simple_switch >/dev/null 2>&1
#sudo  simple_switch translated16.json \
#    -i 0@eth2 -i 1@eth3 \
#    --nanolog ipc:///tmp/bm-0-log.ipc \
#     &
#sleep 2

sudo  ../GTP-Faris-ONDM/behavioral-model/targets/simple_switch/simple_switch ./network_switch_99_flow_id/switch.json --device-id 1 \
    -i 1@eth4 -i 2@eth1 -i 3@eth3 --thrift-port 9090\
     &
sleep 2

sudo ../GTP-Faris-ONDM/behavioral-model/targets/simple_switch/simple_switch_CLI --thrift-port 9090 --json ./network_switch_99_flow_id/switch.json  < ./commands/switch1.txt

echo "READY!!!"
fg
