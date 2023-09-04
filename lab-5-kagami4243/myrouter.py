#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class ArpTable(object):
    Table={}

    def get(self,ipaddr):
        return self.Table.get(ipaddr)

    def update(self,ipaddr,ethaddr):
        self.Table[ipaddr]=ethaddr

class ForwardingTable(object):
    Table=[]

    def __init__(self, interfaces:list)->None:
        for interface in interfaces:
            netaddr=IPv4Network(str(IPv4Address(int(interface.ipaddr)&int(interface.netmask)))+'/'+str(interface.netmask))
            self.Table.append([netaddr,interface.netmask,IPv4Address('0.0.0.0'),interface.name])
        with open('forwarding_table.txt') as lines:
            for line in lines:
                string=line.split(' ')
                netaddr=IPv4Network(string[0]+'/'+string[1])
                self.Table.append([netaddr,IPv4Address(string[1]),IPv4Address(string[2]),string[3].rstrip('\n')])
    
    def query(self,ipaddr:IPv4Address):
        prefix_len=0
        interface=None
        next_addr=None
        for netaddr,netmask,next_addr_1,interface_1 in self.Table:
            if ipaddr in netaddr:
                if netaddr.prefixlen>prefix_len:
                    prefix_len=netaddr.prefixlen
                    interface=interface_1
                    next_addr=next_addr_1
        return [prefix_len,interface,next_addr]
        
class IpQueue(object):
    Table={}

    def get(self,ipaddr):
        return self.Table.get(ipaddr)
    
    def push(self,ipaddr,info:list):
        self.Table[ipaddr]=[info]

    def append(self,ipaddr,info:list):
        self.Table[ipaddr].append(info)

    def delete(self,ipaddr):
        del self.Table[ipaddr]
    
    def get_info(self,ipaddr):
        return list(self.Table[ipaddr])

class ArpQueue(object):
    Table={}

    def get(self,ipaddr):
        return self.Table.get(ipaddr)

    def update(self,ipaddr,info:list):
        self.Table[ipaddr]=info

    def delete(self,ipaddr):
        del self.Table[ipaddr]

    def keys(self):
        return self.Table.keys()     

class Router(object):

    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.Arp_Table=ArpTable()
        self.Forwarding_Table=ForwardingTable(self.net.interfaces())
        self.IP_Queue=IpQueue()
        self.Arp_Queue=ArpQueue()
        
    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        eth = packet.get_header(Ethernet)
        try:
            interface=self.net.interface_by_name(ifaceName)
            if eth.dst!=interface.ethaddr and eth.dst!="ff:ff:ff:ff:ff:ff":
                return
        except:
            return
        if eth.ethertype == EtherType.IPv4:
            ipv4=packet.get_header(IPv4)
            try:
                interface=self.net.interface_by_ipaddr(ipv4.dst)
                if ipv4.protocol == IPProtocol.ICMP and packet[ICMP].icmptype==ICMPType.EchoRequest:
                    icmp=packet.get_header(ICMP)
                    #match
                    [prefix_len,interface,next_addr]=self.match(ipv4.src)
                    if prefix_len==0:
                        return
                    #construct icmppkt
                    icmppkt=Ethernet()+IPv4(src=ipv4.dst,\
                                            dst=ipv4.src,ttl=32,protocol=IPProtocol.ICMP)\
                                    +ICMP(icmptype=ICMPType.EchoReply)
                    icmppkt[ICMP].icmpdata.data=icmp.icmpdata.data
                    icmppkt[ICMP].icmpdata.identifier=icmp.icmpdata.identifier
                    icmppkt[ICMP].icmpdata.sequence=icmp.icmpdata.sequence
                    #forwarding
                    if next_addr == IPv4Address('0.0.0.0'):
                        self.forward(ipv4.src,interface,icmppkt)
                    else:
                        self.forward(next_addr,interface,icmppkt)
                    return
                elif self.is_ICMP_error(packet)==False:
                    #match
                    [prefix_len,interface,next_addr]=self.match(ipv4.src)
                    if prefix_len==0:
                        return
                    # construct ICMP error
                    index=packet.get_header_index(Ethernet)
                    del packet[index]
                    pkt=Ethernet()+IPv4(src=self.net.interface_by_name(interface).ipaddr,dst=ipv4.src,ttl=32\
                        ,protocol=IPProtocol.ICMP)+ICMP()
                    pkt[ICMP].icmptype=ICMPType.DestinationUnreachable
                    pkt[ICMP].icmpcode=ICMPTypeCodeMap[ICMPType.DestinationUnreachable].PortUnreachable
                    pkt[ICMP].icmpdata.data=packet.to_bytes()[:28]
                    #forwarding
                    if next_addr == IPv4Address('0.0.0.0'):
                        self.forward(pkt[IPv4].dst,interface,pkt)
                    else:
                        self.forward(next_addr,interface,pkt)
                    return
                else:
                    return
            except:
                pass

            # match
            [prefix_len,interface,next_addr]=self.match(ipv4.dst)
            if prefix_len==0:
                if self.is_ICMP_error(packet)==True:
                    return
                #match
                [prefix_len,interface,next_addr]=self.match(packet[IPv4].src)
                if prefix_len==0:
                    return
                # construct ICMP error
                index=packet.get_header_index(Ethernet)
                del packet[index]
                pkt=Ethernet()+IPv4(src=self.net.interface_by_name(interface).ipaddr,dst=packet[IPv4].src,ttl=32\
                    ,protocol=IPProtocol.ICMP)+ICMP()
                pkt[ICMP].icmptype=ICMPType.DestinationUnreachable
                pkt[ICMP].icmpcode=ICMPTypeCodeMap[ICMPType.DestinationUnreachable].NetworkUnreachable
                pkt[ICMP].icmpdata.data=packet.to_bytes()[:28]
                #forwarding
                if next_addr == IPv4Address('0.0.0.0'):
                    self.forward(pkt[IPv4].dst,interface,pkt)
                else:
                    self.forward(next_addr,interface,pkt)
                return

            if packet[IPv4].ttl>0:
                packet[IPv4].ttl-=1
            
            if packet[IPv4].ttl==0:
                if self.is_ICMP_error(packet)==True:
                    return
                #match
                [prefix_len,interface,next_addr]=self.match(packet[IPv4].src)
                if prefix_len==0:
                    return
                # construct ICMP error
                index=packet.get_header_index(Ethernet)
                del packet[index]
                pkt=Ethernet()+IPv4(src=self.net.interface_by_name(interface).ipaddr,dst=packet[IPv4].src,ttl=32\
                    ,protocol=IPProtocol.ICMP)+ICMP()
                pkt[ICMP].icmptype=ICMPType.TimeExceeded
                pkt[ICMP].icmpcode=ICMPTypeCodeMap[ICMPType.TimeExceeded].TTLExpired
                pkt[ICMP].icmpdata.data=packet.to_bytes()[:28]
                #forwarding
                if next_addr == IPv4Address('0.0.0.0'):
                    self.forward(pkt[IPv4].dst,interface,pkt)
                else:
                    self.forward(next_addr,interface,pkt)
                return
            # forwading
            if next_addr == IPv4Address('0.0.0.0'):
                self.forward(ipv4.dst,interface,packet)
            else:
                self.forward(next_addr,interface,packet)
        elif eth.ethertype == EtherType.ARP:
            arp=packet.get_header(Arp)
            if arp is None:
                return
            try:
                interface=self.net.interface_by_ipaddr(arp.targetprotoaddr)
                if arp.operation == ArpOperation.Request:
                    self.Arp_Table.update(arp.senderprotoaddr,arp.senderhwaddr)
                    reply=create_ip_arp_reply(interface.ethaddr,arp.senderhwaddr,interface.ipaddr,arp.senderprotoaddr)
                    self.net.send_packet(ifaceName,reply)
                else:
                    if arp.senderhwaddr!='ff:ff:ff:ff:ff:ff':
                        self.Arp_Table.update(arp.senderprotoaddr,arp.senderhwaddr)  
                    self.deal_with_reply(arp)
            except:
                return

    def match(self,ipaddr):
        return self.Forwarding_Table.query(ipaddr)

    def forward(self,ipaddr,interface,packet):
        if self.Arp_Table.get(ipaddr)!=None:
            packet[0].src=(self.net.interface_by_name(interface)).ethaddr
            packet[0].dst=self.Arp_Table.get(ipaddr)
            self.net.send_packet(self.net.interface_by_name(interface),packet)
        elif self.Arp_Queue.get(ipaddr)==None:
            arppacket=Ethernet(src=(self.net.interface_by_name(interface).ethaddr),\
                            dst='ff:ff:ff:ff:ff:ff',\
                            ethertype=EtherType.ARP)\
                            +\
                    Arp(operation=ArpOperation.Request,\
                            senderhwaddr=(self.net.interface_by_name(interface).ethaddr),\
                            senderprotoaddr=self.net.interface_by_name(interface).ipaddr,\
                            targethwaddr='ff:ff:ff:ff:ff:ff',\
                            targetprotoaddr=ipaddr)
            self.net.send_packet(interface,arppacket)
            self.Arp_Queue.update(ipaddr,[interface,arppacket,time.time(),1])
            self.IP_Queue.push(ipaddr,[packet,interface])
        else:
            self.IP_Queue.append(ipaddr,[packet,interface])

    def deal_with_reply(self,arp):
        if self.IP_Queue.get(arp.senderprotoaddr)!=None:
            packets=self.IP_Queue.get(arp.senderprotoaddr)
            for packet in packets:
                packet[0][Ethernet].src=self.net.interface_by_name(packet[1]).ethaddr
                packet[0][Ethernet].dst=arp.senderhwaddr
                self.net.send_packet(packet[1],packet[0]) 
            if self.Arp_Queue.get(arp.senderprotoaddr):
                self.Arp_Queue.delete(arp.senderprotoaddr)
            self.IP_Queue.delete(arp.senderprotoaddr)

    def check_timeout(self):
        for arp in list(self.Arp_Queue.keys()):
            interface,arppacket,last_time,times=self.Arp_Queue.get(arp)
            if time.time()-last_time>1.0:
                if times<5:
                    self.net.send_packet(interface,arppacket)
                    self.Arp_Queue.update(arp,[interface,arppacket,time.time(),times+1])
                else:
                    for info in self.IP_Queue.get_info(arp):
                        packet=info[0]
                        if self.is_ICMP_error(packet)==True:
                            continue
                        ipv4=packet[IPv4]
                        # match
                        [prefix_len,interface,next_addr]=self.match(ipv4.src)
                        if prefix_len==0:
                            return
                        # construct ICMP error
                        index=packet.get_header_index(Ethernet)
                        del packet[index]
                        pkt=Ethernet()+IPv4(src=self.net.interface_by_name(interface).ipaddr,dst=ipv4.src,ttl=32\
                            ,protocol=IPProtocol.ICMP)+ICMP()
                        pkt[ICMP].icmptype=ICMPType.DestinationUnreachable
                        pkt[ICMP].icmpcode=ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable
                        pkt[ICMP].icmpdata.data=packet.to_bytes()[:28]
                        #forwarding
                        if next_addr == IPv4Address('0.0.0.0'):
                            self.forward(pkt[IPv4].dst,interface,pkt)
                        else:
                            self.forward(next_addr,interface,pkt)
                        
                    self.Arp_Queue.delete(arp)
                    self.IP_Queue.delete(arp)
                    return

    def is_ICMP_error(self,packet):
        ipv4=packet.get_header(IPv4)
        if ipv4.protocol == IPProtocol.ICMP:
            if packet[ICMP].icmptype==ICMPType.DestinationUnreachable or packet[ICMP].icmptype==ICMPType.TimeExceeded:
                return True
        return False
        

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.check_timeout()
                continue
            except Shutdown:
                self.check_timeout()
                break

            self.handle_packet(recv)
            self.check_timeout()
            

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
