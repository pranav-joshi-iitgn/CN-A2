#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.nodelib import NAT
from time import sleep

class AssignmentTopo(Topo):

    def addComLink(self,a:str,b:str,ip1,ip2,bw,delay):
        self.addLink(a, b, cls=TCLink, bw=bw, delay=delay)

    def __init__(self,local_MAC='00:e9:3a:a5:d6:35',local_IP='10.7.14.115'):
        Topo.__init__(self)

        # Add hosts with IPs and FQDN labels
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        dns = self.addHost('dns', ip='10.0.0.5/24')

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Host to switch links
        self.addComLink(h1,s1,None,None,100,'2ms')
        self.addComLink(h2,s2,None,None,100,'2ms')
        self.addComLink(h3,s3,None,None,100,'2ms')
        self.addComLink(h4,s4,None,None,100,'2ms')

        # DNS connection to s2
        self.addComLink(dns,s2,None,None,100,'1ms')

        # Inter-switch links (with specified delays)
        self.addComLink(s1,s2,None,None,100,'5ms')
        self.addComLink(s2,s3,None,None,100,'8ms')
        self.addComLink(s3,s4,None,None,100,'10ms')


def run():
    topo = AssignmentTopo()
    net = Mininet(topo=topo, link=TCLink)

    net.addNAT(name='n0').configDefault()
    net.start()

    mininet_log_file = open('mininet.log','w')
    CLI(net,script='mininet_script.txt',stdout=mininet_log_file)
    mininet_log_file.close()

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
