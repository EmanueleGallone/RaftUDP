import argparse

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from raft_definitions import raft_protocol_client_request_port
from scapy.all import *

import struct


def handle(packet):
    print("Got response: " + packet.sprintf("load: %Raw.load%"))


def _get_my_mac():
    # getting mac from interface. ocio a [1]
    return [get_if_hwaddr(i) for i in get_if_list()][1]


def _encode(data, type):
    if type == 'int':
        return struct.pack('<i', data)
    elif type == 'str':
        return struct.pack('I', len(data)) + data


def custom_parser(data):
    try:
        _data = int(data)
        _type = 'int'
    except ValueError:  # so it's a string
        _data = bytes(data, encoding='utf-8')
        _type = 'str'

    return _data, _type


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Raft client')
    parser.add_argument('-s', '--sourceIP', help='raft node sourceIP', type=str)
    parser.add_argument('-d', '--destinationIP', help='raft node destinationIP', type=str)
    parser.add_argument('-da', '--data', help='data to be put inside the cluster', type=str, default=5)
    args = parser.parse_args()

    data, type = custom_parser(args.data)
    data_in_bytes = _encode(data, type)

    # request = raft_packet(
    #     sourceID=0x0,
    #     destinationID=0x1,
    #     data=0x1111,
    #     messageType=COMMANDS['ClientRequest'],
    #     srcIP=args.sourceIP,
    #     dstIP=args.destinationIP,
    #     currentTerm=0x0,
    #     logIndex=0x0
    # )

    bpf = "udp dst port {} and not src host {}".format(raft_protocol_client_request_port, args.sourceIP)
    response_thread = AsyncSniffer(
        filter=bpf,
        prn=lambda _pkt: handle(_pkt),
        count=1,
        timeout=2  # in seconds
    )
    response_thread.start()  # start sniffing for response

    # crafting request packet
    eth = Ether(dst=_get_my_mac())  # don't care. It will be replaced by the switch
    ip = IP(src=args.sourceIP, dst=args.destinationIP)
    udp = UDP(sport=raft_protocol_client_request_port, dport=raft_protocol_client_request_port)

    request = eth / ip / udp / Raw(load=data_in_bytes)

    # sending the request
    sendp(request, count=1, iface=conf.iface, return_packets=False)

    response_thread.join()  # waiting for reply

    if len(response_thread.results) == 0:
        print("Packet lost?")
