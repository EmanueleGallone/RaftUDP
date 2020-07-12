import logging
import struct
import sys
import time

import raft_definitions
from Node import Node
from raft_client import _get_my_mac
from raft_definitions import Raft, IP, COMMANDS, Ether, UDP, raft_protocol_client_request_port, Raw

logging.basicConfig(filename='log.log', level=logging.DEBUG, format='%(asctime)-15s [%(threadName)s] %(message)s')
logger = logging.getLogger()


def _decode(value):
    """converting value from bytes to int"""
    # TODO add support for strings
    return struct.unpack('<i', value)[0]


def handle_new_request(packet):  # TODO finish implementation
    # taking the value sent by the client
    value = _decode(packet[Raw].load)

    is_new_value_in_log = False

    reply_ip = packet[IP].src
    reply_mac = packet[Ether].src

    if n.leader == my_ip:  # it means that I am the leader
        print("correct leader")
        heartbeat_thread.stop()
        is_new_value_in_log = n.new_request(value=value)
        heartbeat_thread.start()
        print("leader log: {}".format(n.log))

    else:
        print("not leader")  # redirect to leader?

    eth = Ether(src=_get_my_mac(), dst=reply_mac)  # don't care. It will be replaced by the switch
    ip = IP(src=n.address, dst=reply_ip)
    udp = UDP(sport=raft_protocol_client_request_port, dport=raft_protocol_client_request_port)

    response = eth / ip / udp / Raw(load=str(is_new_value_in_log))

    time.sleep(0.1)  # without this, client will lose the response
    raft_definitions.send_no_reply(response)


def handle_heartbeat(packet):
    logger.debug("{} received heartbeat from:{}".format(n.address, packet.sprintf("IP:%IP.src%")))

    term, commit_index = n.heartbeat_follower(packet)
    response_ip = packet[IP].src

    command = COMMANDS['HeartBeatResponse']

    message = raft_definitions.raft_packet(
        sourceID=0,
        destinationID=1,
        logIndex=commit_index,
        currentTerm=term,
        dstIP=response_ip,
        srcIP=n.address,
        data=0x0,
        messageType=command
    )

    if packet[Raft].messageType == COMMANDS['AppendEntries']:  # it was an append entry
        # I have to reply with append entry reply to let the leader know that I handled the new value
        message[Raft].messageType = COMMANDS['AppendEntriesReply']
        raft_definitions.send_no_reply(message)
    else:
        raft_definitions.send_no_reply(message)


def handle_vote_request(packet):
    logger.debug("{} handle vote request from {}".format(n.address, packet[IP].src))
    req_term = packet[Raft].currentTerm
    log_index = packet[Raft].logIndex
    requester_ip = packet[IP].src
    staged = None if packet[Raft].data == 0x0 else packet[Raft].data

    choice, term = n.decide_vote(ip=requester_ip, term=req_term, commitIdx=log_index, staged=staged)
    logger.debug("decided: {} , my_term: {}, his_term: {}".format(choice, term, req_term))
    print("decided: {} , my_term: {}, his_term: {}".format(choice, term, req_term))

    voted = 0x1 if choice else 0x0

    message = raft_definitions.raft_packet(
        sourceID=0,
        destinationID=1,
        dstIP=requester_ip,
        srcIP=n.address,  # my ip
        voted=voted,
        currentTerm=term,
        data=0x0,
        logIndex=n.commitIndex,  # CHECK ME
        messageType=COMMANDS['ResponseVote']
    )

    raft_definitions.send_no_reply(message)
    return


if __name__ == '__main__':
    try:
        if len(sys.argv) == 2:
            index = int(sys.argv[1])
            nodes_ips = []

            for ip in raft_definitions.NODES_IPS:
                nodes_ips.append(ip)

            my_ip = nodes_ips.pop(index)

            # initialize node with ip list and its own ip
            n = Node(nodes=nodes_ips, ip=my_ip)

            heartbeat_bpf = "udp dst port {} and not src host {}".format(
                raft_definitions.raft_protocol_heartbeats_port,
                my_ip
            )

            vote_request_bpf = "udp dst port {} and not src host {}".format(
                raft_definitions.raft_protocol_vote_port,
                my_ip
            )

            client_request_bpf = "udp dst port {} and not src host {}".format(
                raft_definitions.raft_protocol_client_request_port,
                my_ip
            )

            heartbeat_thread = raft_definitions.AsyncSniffer(
                filter=heartbeat_bpf,
                prn=lambda _pkt: handle_heartbeat(_pkt)
            )

            vote_thread = raft_definitions.AsyncSniffer(
                filter=vote_request_bpf,
                prn=lambda _pkt: handle_vote_request(_pkt)
            )

            client_thread = raft_definitions.AsyncSniffer(
                filter=client_request_bpf,
                prn=lambda _pkt: handle_new_request(_pkt)
            )

            heartbeat_thread.start()
            vote_thread.start()
            client_thread.start()

            heartbeat_thread.join()
            vote_thread.join()
            client_thread.join()

        else:
            print("usage: python server.py <index> (see NODES_IPS in raft_definitions.py)")

    except KeyboardInterrupt:
        print("KeyboardInterrupt")
