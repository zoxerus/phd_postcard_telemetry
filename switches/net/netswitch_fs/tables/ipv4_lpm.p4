#ifndef __IPV4_LPM__
#define __IPV4_LPM__

control Forwarding(inout headers_t hdr,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata) {

    action ipv4_forward(bit<48> src_mac, bit<48> dst_mac, bit<9> egress_interface) {
        standard_metadata.egress_spec = egress_interface;
        hdr.ethernet.src_addr = src_mac;
        hdr.ethernet.dst_addr = dst_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    action drop() {
        mark_to_drop(standard_metadata);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr : lpm;
        }
        actions = {
            ipv4_forward;
            NoAction;
            drop;

        }
        size = 1024;
        const default_action = drop();

    }

    apply {
        ipv4_lpm.apply();
     }
}

#endif
