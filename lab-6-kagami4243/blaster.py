#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasteeIp=IPv4Address(blasteeIp)
        self.num=int(num)
        self.length=int(length)
        self.senderWindow=int(senderWindow)
        self.begin_time=time.time()
        self.time=time.time()
        self.timeout=int(timeout)
        self.recvTimeout=int(recvTimeout)
        self.lhs=self.rhs=1
        self.Window=list()
        self.Window.append(0)
        self.retrans_list=list()
        self.newpkt_list=list()
        self.reTX=0
        self.TOs=0
        pkt=self.create_packet(self.rhs)
        self.net.send_packet(self.net.interfaces()[0],pkt)
        self.Window.append([pkt,False])

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")
        #ack
        seq=int.from_bytes(packet[3].to_bytes()[:4],'big')
        self.Window[seq][1]=True
        if seq==self.lhs:
            while self.lhs<=self.rhs and self.Window[self.lhs][1] == True:
                self.lhs+=1
            if self.lhs>self.rhs and self.lhs<=self.num:
                newpkt=self.create_packet(self.lhs)
                self.newpkt_list.append(newpkt)
                self.rhs=self.lhs
        #send packet
        if self.retrans_list:
            self.net.send_packet(self.net.interfaces()[0],self.retrans_list[0])
            del self.retrans_list[0]
            if not self.retrans_list:
                self.time=time.time()
            return
        else:
            if self.newpkt_list:
                self.net.send_packet(self.net.interfaces()[0],self.newpkt_list[0])
                self.Window.append([self.newpkt_list[0],False])
                del self.newpkt_list[0]
                self.time=time.time()
                return
            else:
                if self.rhs-self.lhs+1<self.senderWindow:
                    self.rhs+=1
                    pkt=self.create_packet(self.rhs)
                    self.net.send_packet(self.net.interfaces()[0],pkt)
                    self.Window.append([pkt,False])
                    return

    def handle_no_packet(self):
        log_debug("Didn't receive anything")
        if not self.retrans_list:
            self.check_timeout()
        if self.retrans_list:
            self.net.send_packet(self.net.interfaces()[0],self.retrans_list[0])
            del self.retrans_list[0]
            if not self.retrans_list:
                self.time=time.time()
        else:
            if self.newpkt_list:
                self.net.send_packet(self.net.interfaces()[0],self.newpkt_list[0])
                self.Window.append([self.newpkt_list[0],False])
                del self.newpkt_list[0]
                self.time=time.time()
            else:
                if self.rhs-self.lhs+1<self.senderWindow:
                    self.rhs+=1
                    pkt=self.create_packet(self.rhs)
                    self.net.send_packet(self.net.interfaces()[0],pkt)
                    self.Window.append([pkt,False])

        
            
    def create_packet(self,sequence):
        # Creating the headers for the packet
        pkt = Ethernet() + IPv4() + UDP()
        pkt[1].protocol = IPProtocol.UDP

        # Do other things here and send packet
        pkt[0].src='10:00:00:00:00:01'
        pkt[0].dst='40:00:00:00:00:01'
        pkt[0].ethertype=EtherType.IP
        pkt[1].src='192.168.100.1'
        pkt[1].dst='192.168.200.1'
        pkt[1].protocol=IPProtocol.UDP
        pkt+=RawPacketContents(sequence.to_bytes(4,'big')+self.length.to_bytes(2,'big')+(0).to_bytes(self.length,'big'))
        return pkt

    def check_timeout(self):
        if time.time()>self.time+self.timeout/1000:
            i=self.lhs
            while i<=self.rhs:
                if self.Window[i][1]==False:
                    self.retrans_list.append(self.Window[i][0])
                    self.reTX+=1
                i+=1
            self.TOs+=1
        

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(self.recvTimeout/1000)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)
            if self.lhs>self.num:
                break
        log_info(f'Total TX time: {time.time()-self.begin_time}')
        log_info(f'Number of reTX: {self.reTX}')
        log_info(f'Number of coarse TOs: {self.TOs}')
        log_info(f'Throughput (Bps): {(self.num + self.reTX) * self.length / (time.time()-self.begin_time)}')
        log_info(f'Goodput (Bps): {self.num * self.length / (time.time()-self.begin_time)}')
        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
