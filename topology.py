#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import os, subprocess
from mininet.term import makeTerm
import time


def createCustomTopology():

    net = Mininet(controller = RemoteController)

    info( '*** Adding controllers\n' )
    #cA = RemoteController('cA', ip="127.0.0.1", port=6633)
    
    cA = net.addController('cA', controller=RemoteController, ip = "127.0.0.1", port = 6633)

    info( '*** Adding hosts\n' )
    h1 = net.addHost('h1', ip='10.1.1.1', mac='0A:0A:00:00:00:01')
    h2 = net.addHost('h2', ip='10.1.1.2', mac='0A:0A:00:00:00:02')
    h3 = net.addHost('h3', ip='10.1.2.1', mac='0A:0B:00:00:00:01')
    h4 = net.addHost('h4', ip='10.1.2.2', mac='0A:0B:00:00:00:02')

    info( '*** Adding switches\n' )
    s1 = net.addSwitch( 's1', dpid='0000000000000001'  )     #Add dpid as string containing a 16 byte (0 padded) hex equivalent of the int dpid 
    s11 = net.addSwitch( 's11', dpid='000000000000000b' )
    s12 = net.addSwitch( 's12', dpid='000000000000000c' )
    
    
    info( '*** Adding links\n' )
    net.addLink(h1,s11)
    net.addLink(h2,s11)
    
    net.addLink(h3,s12)
    net.addLink(h4,s12)
    
    
    net.addLink(s11,s1)
    net.addLink(s12,s1)
    

    info('*** Starting network\n')
    net.build()
    s1.start([cA])
    s11.start([cA])
    s12.start([cA])
    net.terms += makeTerm(h1)
    #os.system('ryu-manager ryu.app.simple_switch_13 &')
    #time.sleep(10)
    net.pingAll()
    
    info('*** Running CLI\n')
    CLI(net)
    info('*** Stopping network')
    net.stop()
    

if __name__ == '__main__':
    setLogLevel( 'info' )
    createCustomTopology()
