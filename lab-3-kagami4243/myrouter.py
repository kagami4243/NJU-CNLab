#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):

    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.Arp_Table={}

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        eth = packet.get_header(Ethernet)
        arp = packet.get_header(Arp)

        if arp is None:
            log_info("Received a non-Arp packet?!")
            return

        try:
            interface=self.net.interface_by_name(ifaceName)
            if eth.dst!=interface.ethaddr and eth.dst!="ff:ff:ff:ff:ff:ff":
                return
        except:
            return
        
        for interface in self.net.interfaces():
            if interface.ipaddr == arp.targetprotoaddr:
                self.Arp_Table[arp.senderprotoaddr]=arp.senderhwaddr
                log_info(self.Arp_Table)
                if arp.operation == ArpOperation.Request:
                    reply=create_ip_arp_reply(interface.ethaddr,arp.senderhwaddr,interface.ipaddr,arp.senderprotoaddr)
                    self.net.send_packet(ifaceName,reply)
                return

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
