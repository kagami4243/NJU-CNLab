#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterIp=IPv4Address(blasterIp)
        self.num=int(num)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")
        ackpkt=Ethernet(src='20:00:00:00:00:01',dst='40:00:00:00:00:02',ethertype=EtherType.IP)\
                +IPv4(src='192.168.200.1',dst='192.168.100.1',protocol=IPProtocol.UDP)\
                +UDP()
        ackpkt+=RawPacketContents(packet[3].to_bytes()[:4])
        payload_length=int.from_bytes(packet[3].to_bytes()[4:6],'big')
        if payload_length>=8:
            ackpkt+=RawPacketContents(packet[3].to_bytes()[6:6+8])
        else:
            ackpkt+=RawPacketContents(packet[3].to_bytes()[6:]+(0).to_bytes(8-payload_length,'big'))
        log_info(f"blastee send ack:{ackpkt}")
        self.net.send_packet(fromIface,ackpkt)

    def start(self):
        '''A running daemon of the blastee.
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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
