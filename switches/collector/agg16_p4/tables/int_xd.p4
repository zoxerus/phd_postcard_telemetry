#ifndef __INT_XD__
#define __INT_XD__




control ExportData(inout headers_t hdr,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata) {
    /*
    Params: srv_ip = ip address of the telemetry server
            srv_port = transport protocol's port number of the telemetry server
            srv_mac = mac address of the next hop
            egress_interface = interface of the switch to forward the frame
    */
    action forward_postcard(bit<32> srv_ip,
         bit<16> srv_port,
         bit<48> srv_mac,
         bit<16> udp_src,
         bit<9> egress_interface ){

        standard_metadata.egress_spec = egress_interface;

        hdr.ethernet.setValid();
        hdr.ethernet.ether_type = ETH_TYPE_IPV4;
        hdr.ethernet.dst_addr = srv_mac;
        hdr.ethernet.src_addr = 0x0a0a0a0b0b0b;

        // adding new ip header to the postcard packet
        hdr.ipv4.setValid();
        hdr.ipv4.version = IP_VERSION_4;
        hdr.ipv4.ihl = IPV4_IHL_MIN;
        hdr.ipv4.diffserv = 8w0;


        hdr.ipv4.totalLen = (bit<16>)(IPV4_MIN_LEN +
                UDP_LEN + GROUP_LENGTH + REPORT_AGG_LEN);

        hdr.ipv4.identification = 0;
        hdr.ipv4.flags = 0;
        hdr.ipv4.fragOffset = 0;
        hdr.ipv4.src_addr = 0x0a00000b;
        hdr.ipv4.dst_addr = srv_ip; // collector address
        hdr.ipv4.ttl = 64; // new time to live
        hdr.ipv4.protocol = IP_PROTO_UDP;

        // adding new UDP header to the postcard packet
        hdr.udp.setValid();
        hdr.udp.src_port = udp_src;
        hdr.udp.dst_port = srv_port;
        hdr.udp.udp_length = (bit<16>)(UDP_LEN + GROUP_LENGTH + REPORT_AGG_LEN);


        // remove any extra payload in the packet
        truncate((bit<32>)(hdr.ipv4.totalLen + ETH_LEN));
        log_msg("postcard forwarded");
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
