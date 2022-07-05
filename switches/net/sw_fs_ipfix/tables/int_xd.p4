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
        hdr.xd_ipv4.totalLen = (bit<16>)(IPV4_MIN_LEN + UDP_LEN + IPFIX_LEN);

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
        hdr.xd_udp.udp_length = (bit<16>)(UDP_LEN + IPFIX_LEN);



        hdr.ipfix.setValid();
        hdr.ipfix.msg.version_number = 10;
        hdr.ipfix.msg.message_length = IPFIX_LEN;
        hdr.ipfix.msg.export_time = (bit<32>) local_metadata.egress_tstamp;
        hdr.ipfix.msg.sequence_number = local_metadata.seq_num;
        hdr.ipfix.msg.observation_domain = sw_id;

        hdr.ipfix.set.set_id = DATA_RECORD_ID;
        hdr.ipfix.set.set_length = SET_LEN;

        hdr.ipfix.record.flow_id = local_metadata.flow_id;
        hdr.ipfix.record.ttl = local_metadata.ttl;
        hdr.ipfix.record.deq_depth = (bit<24>)local_metadata.deq_qdepth;
        hdr.ipfix.record.enq_depth = (bit<24>)local_metadata.enq_qdepth;
        hdr.ipfix.record.ingress_tstamp = local_metadata.ingress_tstamp;
        hdr.ipfix.record.egress_tstamp = local_metadata.egress_tstamp;
        hdr.ipfix.record.ingress_interface = (bit<16>)local_metadata.ingress_interface;
        hdr.ipfix.record.egress_interface = (bit<16>)local_metadata.egress_interface;

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
