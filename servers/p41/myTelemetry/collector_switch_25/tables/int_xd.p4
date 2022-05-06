#ifndef __INT_XD__
#define __INT_XD__




control ExportData(inout headers_t hdr,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata) {

    action forward_postcard(bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.xd_ethenet_header.setValid();
        hdr.xd_ethenet_header.ether_type = ETH_TYPE_IPV4;
        hdr.xd_ethenet_header.dst_addr = 0x0a0b0c0d0a0b;
        hdr.xd_ethenet_header.src_addr = 0x0a0a0a0b0b0b;

        // adding new ip header to the postcard packet
        hdr.xd_ip_header.setValid();
        hdr.xd_ip_header.version = IP_VERSION_4;
        hdr.xd_ip_header.ihl = IPV4_IHL_MIN;
        hdr.xd_ip_header.diffserv = 8w0;

        bit<16> telemetryLength = 500;


        hdr.xd_ip_header.totalLen = (bit<16>)IPV4_MIN_HEAD_LEN +
                (bit<16>)UDP_HEADER_LEN + telemetryLength;

        hdr.xd_ip_header.identification = 0;
        hdr.xd_ip_header.flags = 0;
        hdr.xd_ip_header.fragOffset = 0;
        hdr.xd_ip_header.srcAddr = 0x0a00000b;
        hdr.xd_ip_header.dstAddr = 0x0a00000a; // 10.0.0.1 collector address
        hdr.xd_ip_header.ttl = 64; // new time to live
        hdr.xd_ip_header.protocol = IP_PROTO_UDP;

        // adding new UDP header to the postcard packet
        hdr.xd_udp_header.setValid();
        hdr.xd_udp_header.src_port = 22222;
        hdr.xd_udp_header.dst_port = 54321;
        hdr.xd_udp_header.udp_length = (bit<16>)UDP_HEADER_LEN + telemetryLength;


        truncate((bit<32>)hdr.xd_ip_header.totalLen + (bit<32>) ETH_HEADER_LEN);

        // hdr.ethernet = hdr.xd_ethenet_header;
        // hdr.ipv4 = hdr.xd_ip_header;
        // hdr.udp = hdr.xd_udp_header;

        // hdr.int_xd.setValid();
        // hdr.int_xd.switch_id = sw_id;
        // hdr.int_xd.latency = local_metadata.latency;
        // hdr.int_xd.enq_depth = local_metadata.enq_qdepth;
        // hdr.int_xd.deq_depth = local_metadata.deq_qdepth;
        // log_msg("\nAfterClone:\n\tlatancey:\t{}\n\tenq_qdepth:\t{}\n\tdeq_qdepth:\t{}",
        //         {local_metadata.latency,
        //              local_metadata.enq_qdepth,
        //              local_metadata.deq_qdepth} );
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table table_postcard {
        key = { }
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
