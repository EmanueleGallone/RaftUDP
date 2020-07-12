#ifndef _PARSER_P4_
#define _PARSER_P4_


#define ETHERTYPE_IPV4 16w0x0800
#define UDP_PROTOCOL 8w0x11
#define RAFT_PROTOCOL 16w0x9998


parser TopParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            UDP_PROTOCOL : parse_udp;
            default : accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            RAFT_PROTOCOL : parse_raft;
            default : accept;
        }
    }

    state parse_raft {
        packet.extract(hdr.raft);
        transition accept;
    }
}

control TopDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.raft);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    //Checksum16() ipv4_checksum;
    apply {
        // if (hdr.ipv4.hdrChecksum == ipv4_checksum.get({
        //                                 hdr.ipv4.version,
        //                                 hdr.ipv4.ihl,
        //                                 hdr.ipv4.diffserv,
        //                                 hdr.ipv4.totalLen,
        //                                 hdr.ipv4.identification,
        //                                 hdr.ipv4.flags,
        //                                 hdr.ipv4.fragOffset,
        //                                 hdr.ipv4.ttl,
        //                                 hdr.ipv4.protocol,
        //                                 hdr.ipv4.srcAddr,
        //                                 hdr.ipv4.dstAddr
        //                             }))
        //     mark_to_drop();
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    //Checksum16() ipv4_checksum;

    apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

#endif