#ifndef _HEADERS_P4_
#define _HEADERS_P4_

typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address;
typedef bit<4> PortId;

typedef bit<9>  egressSpec_t;

// Physical Ports
const PortId DROP_PORT = 0xF;

// standard headers
header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    IPv4Address srcAddr;
    IPv4Address dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

// Headers for Raft
// NB: If you change bit sizes here remember to change also in raft_definitions.py the type of field inside the packet crafter!!!!
#define BOOLEAN 8
#define BYTE 8
#define MAX_DATA_SIZE 32
#define MAX_LOG_SIZE 16
#define MAX_TERM_SIZE 16
#define MAX_FOLLOWER_SIZE 16

header raft_t {
    //NB: BMV2 SUPPORTS ONLY HEADERS MULTIPLE OF 8
    //NB: IF YOU ADD MORE HEADERS, ADD THEM IN raft_definitions.py!
    //otherwise the switches won't intercept the message (maybe because of the isValid())

    bit<MAX_FOLLOWER_SIZE> sourceID; //Id of the current leader

    bit <MAX_FOLLOWER_SIZE> destinationID;

    bit<MAX_LOG_SIZE> logIndex; // index of the last entry on Leader's log
    
    bit<MAX_TERM_SIZE> currentTerm; //or Epoch
    
    bit<MAX_DATA_SIZE> data; // actual value to be pushed inside the log
    
    bit<BOOLEAN> committed;  //boolean to return to source

    bit<BYTE> messageType; //represents the command

    bit<BYTE> vooted; //represent the vote boolean
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    raft_t raft;
}

struct raft_metadata_t {
    bit<1> set_drop; //? maybe useless
    bit<8> heartbeat_count; // maybe useless
    bit<MAX_TERM_SIZE> currentTerm;
}

struct metadata {
    raft_metadata_t   raft_metadata;
}

#endif
