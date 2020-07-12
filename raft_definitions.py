from scapy.all import *
from scapy.layers.inet import UDP, IP
import random

from scapy.layers.l2 import Ether


class Raft(Packet):
    name = "RaftPacket "
    fields_desc = [
        XShortField("sourceID", 0x0),  # defined as 'field(name, default_value)'
        XShortField("destinationID", 0x0),
        XShortField("logIndex", 0x0),
        XShortField("currentTerm", 0x0),
        XIntField("data", 0x0),
        XByteField("committed", 0x0),
        XByteField("messageType", 0x0),
        XByteField("voted", 0x0)
    ]


# GLOBALS

STATUSES = {'follower': 0, 'candidate': 1, 'leader': 2}
NODES_IPS = ['10.0.1.1', '10.0.2.2', '10.0.3.3']

RANDOM_TIMEOUT = {'min': 1500, 'max': 2000}  # min max values in ms
REQUEST_TIMEOUT = 200  # in ms
MAX_LOG_WAIT = 500
HEARTBEAT_TIME = 500
RECOVER_TIME = 1000  # time in which the leader sends periodically recover messages for the nodes that were down

raft_protocol_dstport = 0x9998  # raft protocol identifier on port 9998 see parser.p4
raft_protocol_vote_port = 0x9997  # 39319
raft_protocol_heartbeats_port = 0x9996  # 39318

raft_protocol_client_request_port = 0x9994


raft_protocol_ports_list = [
    raft_protocol_vote_port,
    raft_protocol_heartbeats_port,
    raft_protocol_dstport
]

bind_layers(UDP, Raft, dport=raft_protocol_dstport)
bind_layers(UDP, Raft, dport=raft_protocol_heartbeats_port)
bind_layers(UDP, Raft, dport=raft_protocol_vote_port)

COMMANDS = {
    'HeartBeatRequest': 0x1,
    'AppendEntries': 0x2,
    'HeartBeatResponse': 0x3,
    'RequestVote': 0x4,
    'ResponseVote': 0x5,
    'CommitValue': 0x6,
    'AppendEntriesReply': 0x7,
    'RecoverEntries': 0x8
            }

# END OF GLOBALS


def raft_packet(sourceID,
                destinationID,
                logIndex,
                currentTerm,
                data,
                srcIP,
                dstIP,
                messageType,
                committed=0x0,
                voted=0x0):

    """helper method to craft a Raft packet"""
    custom_mac = "08:00:27:10:a8:80"  # don't care. The switch will replace it automatically

    eth = Ether(dst=custom_mac)
    ip = IP(src=srcIP, dst=dstIP)
    udp = UDP(sport=raft_protocol_dstport, dport=raft_protocol_dstport)

    _packet = eth / ip / udp / Raft(sourceID=sourceID,
                                    destinationID=destinationID,
                                    logIndex=logIndex,
                                    currentTerm=currentTerm,
                                    data=data,
                                    committed=committed,
                                    messageType=messageType,
                                    voted=voted)

    return _packet


def send_raft_vote_request(nodeIP, message):
    message[UDP].dport = raft_protocol_vote_port

    reply = None

    _thread = AsyncSniffer(
        filter="ip src host {}".format(nodeIP),
        lfilter=is_raft_packet_vote_response,
        count=1,
    )
    _thread.start()

    sendp(message, iface=conf.iface, count=1, return_packets=False, verbose=False)
    _thread.join()

    if len(_thread.results) != 0:
        reply = _thread.results.pop()

    return reply


def send_raft_heartbeat(nodeIP, message):
    message[UDP].dport = raft_protocol_heartbeats_port

    reply = None

    _thread = AsyncSniffer(
        filter="ip src host {}".format(nodeIP),
        lfilter=is_raft_packet_heartbeat_response,
        count=1,
        timeout=REQUEST_TIMEOUT // 1000
    )
    _thread.start()

    sendp(message, iface=conf.iface, count=1, return_packets=False, verbose=False)
    _thread.join()

    if len(_thread.results) != 0:
        reply = _thread.results.pop()

    return reply


def send_raft_heartbeat_with_log(nodeIP, message):
    message[UDP].dport = raft_protocol_heartbeats_port

    reply = None

    _thread = AsyncSniffer(
        filter="ip src host {}".format(nodeIP),
        lfilter=is_raft_packet_heartbeat_with_log_response,
        count=1,
        timeout=1  # in seconds. Achtung! this gave me quite the headache to find this bug
    )
    _thread.start()

    time.sleep(0.1)
    sendp(message, iface=conf.iface, count=1, return_packets=False, verbose=False)
    _thread.join()

    if len(_thread.results) != 0:
        reply = _thread.results.pop()

    return reply


def send_no_reply(message):
    sendp(message, iface=conf.iface, count=1, return_packets=False, verbose=False)


def is_raft_packet_vote_response(_packet):
    if _packet.haslayer(IP):
        if not _packet[IP].proto == 'icmp':
            if _packet.haslayer(UDP):
                # if _packet[UDP].dport == raft_protocol_dstport:
                if _packet[UDP].dport in raft_protocol_ports_list:
                    if _packet.haslayer(Raft):
                        if _packet[Raft].messageType == COMMANDS['ResponseVote']:
                            return True
    return False


def is_raft_packet_heartbeat_response(_packet):
    if _packet.haslayer(IP):
        if not _packet[IP].proto == 'icmp':
            if _packet.haslayer(UDP):
                # if _packet[UDP].dport == raft_protocol_dstport:
                if _packet[UDP].dport in raft_protocol_ports_list:
                    if _packet.haslayer(Raft):
                        if _packet[Raft].messageType == COMMANDS['HeartBeatResponse']:
                            return True
    return False


def is_raft_packet_heartbeat_with_log_response(_packet):
    if _packet.haslayer(IP):
        if not _packet[IP].proto == 'icmp':
            if _packet.haslayer(UDP):
                if _packet[UDP].dport == raft_protocol_dstport:
                # if _packet[UDP].dport == raft_protocol_log_replication_port:
                    if _packet.haslayer(Raft):
                        if _packet[Raft].messageType == COMMANDS['AppendEntriesReply']:
                            return True
    return False


def raft_timeout():
    return random.randrange(RANDOM_TIMEOUT['min'], RANDOM_TIMEOUT['max']) / 1000
