#include <core.p4>
#include <v1model.p4>
#include "includes/header.p4"
#include "includes/parser.p4"

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action _drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(EthernetAddress dstAddr, egressSpec_t port) {

        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

    }

    table ipv4_lpm { //ipv4 longest prefix
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            _drop;
            NoAction;
        }
        size = 1024;
        default_action = _drop();
    }

    apply {
        if (hdr.ipv4.isValid()) { //Layer 3 handling
            ipv4_lpm.apply();
        }
    }

}

//////////////////EGRESS////////////////////////////////

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    apply {}
}

/////////////////////////SWITCH/////////////////////////

V1Switch(TopParser(), verifyChecksum(), MyIngress(), egress(), computeChecksum(), TopDeparser()) main;