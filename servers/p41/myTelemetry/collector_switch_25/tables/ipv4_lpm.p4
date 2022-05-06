#ifndef __IPV4_LPM__
#define __IPV4_LPM__

control Forwarding(inout headers_t hdr,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata) {

    action ipv4_forward(bit<48> mac , bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        local_metadata.is_forwarded = 1;
    }


    action drop() {
        mark_to_drop(standard_metadata);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr : lpm;
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
