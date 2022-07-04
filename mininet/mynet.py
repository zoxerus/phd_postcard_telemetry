#!/usr/bin/env python3
# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink

from p4_mininet import P4Switch, P4Host

import argparse
from time import sleep

parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", required = True)
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
parser.add_argument('--num-hosts', help='Number of hosts to connect to switch',
                    type=int, action="store", default=2)
parser.add_argument('--mode', choices=['l2', 'l3'], type=str, default='l3')
parser.add_argument('--json-collector', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--json-netswitch', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    type=str, action="store", required=False, default=False)
parser.add_argument('--debugger', help='Enable Debugger',
                    type=str, action="store", required=False, default=False)
parser.add_argument('--log-level', help="Set log level, vales are:'trace','debug',                      +\
                                    'info', 'warn', 'error', 'off', default is 'info' ",
                                    type = str,action='store', required=False, default='info')
args = parser.parse_args()


class MyTopo(Topo):
    "Single switch connected to n (< 256) hosts."
    def __init__(self, sw_path, json_collector, json_netswitch, thrift_port, pcap_dump, enable_debugger, n, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        s0 = self.addSwitch('s0',
                                sw_path = sw_path,
                                json_path = json_collector,
                                thrift_port = 9090,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )

        s1 = self.addSwitch('s1',
                                sw_path = sw_path,
                                json_path = json_netswitch,
                                thrift_port = 9091,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )
        s2 = self.addSwitch('s2',
                                sw_path = sw_path,
                                json_path = json_netswitch,
                                thrift_port = 9092,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )
        s3 = self.addSwitch('s3',
                                sw_path = sw_path,
                                json_path = json_netswitch,
                                thrift_port = 9093,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )

        h1 = self.addHost('h1',
                            ip = "10.0.11.10/24",
                            mac = 'AB:CD:10:00:11:10',
                            commands = ["route add default gw 10.0.11.1 dev eth0",
                            "arp -i eth0 -s 10.0.11.1 AB:CD:10:00:11:01"])
        h2 = self.addHost('h2',
                            ip = '10.0.12.10/24',
                            mac = 'AB:CD:10:00:12:10',
                            commands = ["route add default gw 10.0.12.1 dev eth0",
                            "arp -i eth0 -s 10.0.12.1 AB:CD:10:00:12:01"])
        h3 = self.addHost('h3',
                            ip = "10.0.31.10/24",
                            mac = 'AB:CD:10:00:31:10',
                            commands = ["route add default gw 10.0.31.1 dev eth0",
                            "arp -i eth0 -s 10.0.31.1 AB:CD:10:00:31:01"])


        self.addLink(s0, s1, 1, 1)
        self.addLink(s0, s2, 2, 1)
        self.addLink(s0, s3, 3, 1)
        self.addLink(s1, s2, 2, 2)
        self.addLink(s2, s3, 3, 2)
        self.addLink(s1, h1, 3, 0)
        self.addLink(s1, h2, 4, 0)
        self.addLink(s3, h3, 3, 0)




def main():
    num_hosts = args.num_hosts
    mode = args.mode

    topo = MyTopo(args.behavioral_exe,
                            args.json_collector,
                            args.json_netswitch,
                            args.thrift_port,
                            args.pcap_dump,
                            args.debugger,
                            num_hosts
                            )
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
                  link=TCLink,
                  controller = None)

    #net.addNAT().configDefault()
    net.start()
    s0 = net.get('s0')
    s0.setMAC('AB:CD:10:10:00:01', intf = 's0-eth1')
    s0.setMAC('AB:CD:10:20:00:01', intf = 's0-eth2')
    s0.setMAC('AB:CD:10:30:00:01', intf = 's0-eth3')
    #s0.setMAC('20:1a:06:4e:99:fb', intf = 'enp1s0f0')

    s0.setIP('10.10.0.1/30', intf='s0-eth1')
    s0.setIP('10.20.0.1/30', intf='s0-eth2')
    s0.setIP('10.30.0.1/30', intf='s0-eth3')
    #s0.setIP('10.30.2.173/32', intf='enp1s0f0')

    s1 = net.get('s1')
    s1.setMAC('AB:CD:10:10:00:02', intf = 's1-eth1')
    s1.setMAC('AB:CD:10:12:00:01', intf = 's1-eth2')
    s1.setMAC('AB:CD:10:00:11:01', intf = 's1-eth3')
    s1.setMAC('AB:CD:10:00:12:01', intf = 's1-eth4')

    s1.setIP('10.10.0.2/30', intf = 's1-eth1')
    s1.setIP('10.12.0.1/30', intf = 's1-eth2')
    s1.setIP('10.0.11.1/24', intf = 's1-eth3')
    s1.setIP('10.0.12.1/24', intf = 's1-eth4')

    s2 = net.get('s2')
    s2.setMAC('AB:CD:10:20:00:02', intf = 's2-eth1')
    s2.setMAC('AB:CD:10:12:00:02', intf = 's2-eth2')
    s2.setMAC('AB:CD:10:23:00:01', intf = 's2-eth3')

    s2.setIP('10.20.0.2/30', intf = 's2-eth1')
    s2.setIP('10.12.0.2/30', intf = 's2-eth2')
    s2.setIP('10.23.0.1/30', intf = 's2-eth3')

    s3 = net.get('s3')
    s3.setMAC('AB:CD:10:30:00:02', intf = 's3-eth1')
    s3.setMAC('AB:CD:10:23:00:02', intf = 's3-eth2')
    s3.setMAC('AB:CD:10:00:31:01', intf = 's3-eth3')

    s3.setIP('10.30.0.2/30', intf = 's3-eth1')
    s3.setIP('10.23.0.2/30', intf = 's3-eth2')
    s3.setIP('10.0.31.1/24', intf = 's3-eth3')

    h1 = net.get('h1')
    h1.setARP('10.0.11.1', 'AB:CD:10:00:11:01')
    h1.setDefaultRoute("dev eth0 via %s" % '10.0.11.1')
    h1.describe()

    h2 = net.get('h2')
    h2.setARP('10.0.12.1', 'AB:CD:10:00:12:01')
    h2.setDefaultRoute("dev eth0 via %s" % '10.0.12.1')
    h2.describe()

    h3 = net.get('h3')
    h3.setARP('10.0.31.1', 'AB:CD:10:00:31:01')
    h3.setDefaultRoute("dev eth0 via %s" % '10.0.31.1')
    h3.describe()

    print("Ready !")

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
