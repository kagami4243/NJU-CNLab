'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
import time
from switchyard.lib.userlib import *

class Forwarding_Table(object):
    forwarding_table={}
    size=0
    MAX_SIZE=5

    def update_in(self,src,port):
        intf=self.forwarding_table.get(src)
        if intf!=None:
            self.forwarding_table[src]=(port,self.forwarding_table[src][1])
        else:
            self.size+=1
            if self.size>self.MAX_SIZE:
                ans=min(self.forwarding_table,key=lambda x:self.forwarding_table[x][1])
                del self.forwarding_table[ans]
                self.forwarding_table[src]=(port,time.time())
            else:
                self.forwarding_table[src]=(port,time.time())

    def update_out(self,dst):
        self.forwarding_table[dst]=(self.forwarding_table[dst][0],time.time())

    def get(self,dst):
        intf=self.forwarding_table.get(dst)
        if intf==None:
            return None
        return intf[0]

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    forwarding_table=Forwarding_Table()
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        forwarding_table.update_in(eth.src,fromIface)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            intf=forwarding_table.get(eth.dst)
            if intf!=None and eth.dst!='ff:ff:ff:ff:ff:ff':
                log_info (f"Flooding packet {packet} to {intf}")
                forwarding_table.update_out(eth.dst)
                net.send_packet(intf, packet)
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
