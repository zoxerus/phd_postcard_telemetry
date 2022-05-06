#ifndef __INT_XD__
#define __INT_XD__


control ExportData(inout headers_t hdr,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata) {

    action forward_postcard(bit<9> port, bit<32> sw_id) {
        standard_metadata.egress_spec = port;
        hdr.xd_ethenet_header.setValid();
        hdr.xd_ethenet_header.ether_type = ETH_TYPE_IPV4;

        // adding new ip header to the postcard packet
        hdr.xd_ip_header.setValid();
        hdr.xd_ip_header.version = IP_VERSION_4;
        hdr.xd_ip_header.ihl = IPV4_IHL_MIN;
        hdr.xd_ip_header.diffserv = 8w0;
        hdr.xd_ip_header.totalLen = (bit<16>)IPV4_MIN_HEAD_LEN +
                (bit<16>)UDP_HEADER_LEN + (bit<16>)REPORT_FIXED_HEADER_LEN +
                (bit<16>)ETH_HEADER_LEN + hdr.ipv4.totalLen;

        hdr.xd_ip_header.identification = 0;
        hdr.xd_ip_header.flags = 0;
        hdr.xd_ip_header.fragOffset = 0;
        hdr.xd_ip_header.src_addr = sw_id;
        hdr.xd_ip_header.dst_addr = 0x0a00000a; // 10.0.0.1 collector address
        hdr.xd_ip_header.ttl = 64; // new time to live
        hdr.xd_ip_header.protocol = IP_PROTO_UDP;

        // adding new UDP header to the postcard packet
        hdr.xd_udp_header.setValid();
        hdr.xd_udp_header.src_port = 2222;
        hdr.xd_udp_header.dst_port = 54321;
        hdr.xd_udp_header.udp_length = (bit<16>)UDP_HEADER_LEN +
                (bit<16>)REPORT_FIXED_HEADER_LEN + (bit<16>)ETH_HEADER_LEN +
                (bit<16>)IPV4_MIN_HEAD_LEN + (bit<16>)hdr.udp.udp_length;

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
        hdr.int_xd.seq_no = local_metadata.flow_id;     // using this field as a flow_id
        hdr.int_xd.ingress_tstamp = local_metadata.ingress_tstamp;
        hdr.int_xd.engress_tstamp = local_metadata.egress_tstamp;
        // log_msg("\nAfterClone:\n\tlatancey:\t{}\n\tenq_qdepth:\t{}\n\tdeq_qdepth:\t{}",
        //         {local_metadata.latency,
        //              local_metadata.enq_qdepth,
        //              local_metadata.deq_qdepth} );
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table table_postcard {
        key = {}
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
