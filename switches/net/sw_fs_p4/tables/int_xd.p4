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
        hdr.xd_ipv4.totalLen = (bit<16>)(IPV4_MIN_LEN + UDP_LEN + GROUP_LENGTH + REPORT_LENGTH);

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
        hdr.xd_udp.udp_length = (bit<16>)(UDP_LEN + GROUP_LENGTH + REPORT_LENGTH);

        hdr.group_header.setValid();
        hdr.group_header.version = 2;
        hdr.group_header.hw_id = 0;
        hdr.group_header.sequence_number = local_metadata.seq_num;
        hdr.group_header.node_id = sw_id;

        hdr.report.setValid();
        hdr.report.reptype = 0;
        hdr.report.intype = 1;
        hdr.report.report_length = 12;
        hdr.report.md_length = 10;
        hdr.report.dropped = 0;
        hdr.report.cqa = 0;
        hdr.report.tfa = 0;
        hdr.report.i_rep = 0;
        hdr.report.rsvd = 0;
        hdr.report.md_bits = 0b0111111110000001;
        hdr.report.ds_id = 0;
        hdr.report.ds_bits = 0;
        hdr.report.ds_status = 0;
        hdr.report.l1_in_id = (bit<16>)local_metadata.ingress_interface;
        hdr.report.l1_out_id = (bit<16>)local_metadata.egress_interface;
        hdr.report.latency = (bit<32>)(local_metadata.egress_tstamp -
                                                local_metadata.ingress_tstamp);
        hdr.report.qoc_id = 0;
        bit<24> ran_qoc;
        random<bit<24>>(ran_qoc,20,30);
        log_msg("ran_qoc: {}",{ran_qoc});
        hdr.report.q_occupancy = ran_qoc; //(bit<24>)local_metadata.deq_qdepth;
        hdr.report.ingress_tstamp = (bit<64>)local_metadata.ingress_tstamp;
        hdr.report.egress_tstamp = (bit<64>)local_metadata.egress_tstamp;
        hdr.report.l2_in_id = 0x0a000b01;
        hdr.report.l2_out_id = 0x0a000c01;
        bit<32> ran_tx;
        random<bit<32>>(ran_tx,5,15);
        log_msg("ran_tx: {}",{ran_tx});
        hdr.report.egress_tx_use = ran_tx;
        hdr.report.buffer_id = 0;
        random<bit<24>>(ran_qoc,10,22);
        log_msg("ran_buf: {}",{ran_qoc});
        hdr.report.buffer_occupancy = (bit<24>)local_metadata.enq_qdepth;
        hdr.report.qdr_id = 0;
        hdr.report.drop_reason =0;
        hdr.report.padding = 0;

        truncate( (bit<32>)hdr.xd_ipv4.totalLen + ETH_LEN );
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
