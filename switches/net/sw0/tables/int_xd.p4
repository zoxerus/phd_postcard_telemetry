#ifndef __INT_XD__
#define __INT_XD__


control ExportData(inout headers_t hdr,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata) {

    action forward_postcard(bit<9> port, bit<32> sw_id, bit<16> src_port, bit<32> srv_ip, bit<16> srv_prt, bit<48> src_mac, bit<48> dst_mac) {
        standard_metadata.egress_spec = port;
        hdr.xd_ethernet.setValid();
        hdr.xd_ethernet.ether_type = ETH_TYPE_IPV4;
        hdr.xd_ethernet.src_addr = src_mac;
        hdr.xd_ethernet.dst_addr = dst_mac;

        // adding new ip header to the postcard packet
        hdr.xd_ipv4.setValid();
        hdr.xd_ipv4.version = IP_VERSION_4;
        hdr.xd_ipv4.ihl = IPV4_IHL_MIN;
        hdr.xd_ipv4.diffserv = 8w0;
        hdr.xd_ipv4.totalLen = (bit<16>)IPV4_MIN_HEAD_LEN +
                (bit<16>)UDP_HEADER_LEN + (bit<16>)REPORT_FIXED_HEADER_LEN_BYTES;

        hdr.xd_ipv4.identification = 0;
        hdr.xd_ipv4.flags = 0;
        hdr.xd_ipv4.fragOffset = 0;
        hdr.xd_ipv4.src_addr = sw_id;
        hdr.xd_ipv4.dst_addr = srv_ip; // 10.0.0.1 collector address
        hdr.xd_ipv4.ttl = 64; // new time to live
        hdr.xd_ipv4.protocol = IP_PROTO_UDP;

        // adding new UDP header to the postcard packet
        hdr.xd_udp.setValid();
        hdr.xd_udp.src_port = src_port;
        hdr.xd_udp.dst_port = srv_prt;
        hdr.xd_udp.udp_length = (bit<16>)UDP_HEADER_LEN +
                (bit<16>)REPORT_FIXED_HEADER_LEN_BYTES;

        hdr.int_xd.setValid();
        hdr.int_xd.ver = 0b0001;
        hdr.int_xd.len = 0b1111;
        hdr.int_xd.nproto = 0b010;
        hdr.int_xd.rep_md_bits = 0b010101;
        hdr.int_xd.d = 0b1;
        hdr.int_xd.q = 0b1;
        hdr.int_xd.f = 0b1;
        hdr.int_xd.rsvd = 0b111100;
        hdr.int_xd.hw_id = 0b111111;
        hdr.int_xd.sw_id = sw_id;
        hdr.int_xd.seq_no = 0;
        hdr.int_xd.ingress_tstamp = local_metadata.ingress_tstamp;
        hdr.int_xd.engress_tstamp = local_metadata.egress_tstamp;

        truncate( (bit<32>) hdr.xd_ipv4.totalLen + (bit<32>)ETH_HEADER_LEN );
        hdr.ethernet.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.udp.setInvalid();
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table table_postcard {
        key = {
            // hdr.xd_udp.src_port : exact;
        }
        actions = {
            forward_postcard;
            NoAction;
        }
        const default_action = NoAction();

    }

    apply {
        table_postcard.apply();
     }
}

#endif
