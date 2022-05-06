#include <core.p4>
#incldue <v1model.p4>

#include "lib/packet_parsers.p4"
#include "tables/ipv4_lpm.p4"
#include "tables/postcard_detect.p4"
#include "lib/packet_headers.p4"
#include "lib/utils.p4"


control MyVerifyChecksum(inout headers_t hdr, inout local_metadata_t meta) {
    apply {  }
}

control MyIngress (
        inout headers_t hdr,
        inout local_metadata_t local_metadata,
        inout standard_metadata_t standard_metadata){


    // the number of flows
    const bit<32> number_of_flows = 4;
    const bit<32> number_of_switches = 3;

    // create a register array to save the telemetry data
    // use the length of the telemetry enteries to set the register size inside << >>
    // and array length in between ()
    // register <bit<32>> ( PACKET_AGGREGATOR_THRESHOLD * number_of_flows * number_of_switches )  flow_aggregator;
    register <bit<32>> ( number_of_flows * number_of_switches )  flow_aggregator;


    // a single register to hold the pointer location
    // the pointer points to the last register in the register array that was written to
    register <bit<32>> (number_of_flows * number_of_switches) aggregator_pointer;

    // register <bit<32>> (number_of_flows) flow_latency_register;
    // bit<32> flow_latency_value;

    // a variable to store the value of the pointer
    bit <32> cursor;

    bit <32> data = 0;
    apply {
        if ( hdr.ipv4.isValid() ){
            // use a match table to check the destination IP and port in order to
            // determine whether this packet is a telemetry postcard
            PostcardDetect.apply(hdr, local_metadata, standard_metadata);
            // if packet is a postcard then apply postcard processing
            // else just forward the packet to the next hop
            if( local_metadata.is_postcard == 1){

                bit<32> cursor_location = local_metadata.flow_register_number * number_of_switches
                                    + local_metadata.switch_register_number;


                // log_msg("cursor_location: {}, flow: {}, switch: {}",
                //      {cursor_location, local_metadata.flow_register_number,
                //          local_metadata.switch_register_number });


                aggregator_pointer.read(cursor, cursor_location);


                data = data + (hdr.int_xd.engress_tstamp - hdr.int_xd.ingress_tstamp )/8 ;

                // bit<32> reg = ( local_metadata.flow_register_number * number_of_switches +
                //     local_metadata.switch_register_number )* PACKET_AGGREGATOR_THRESHOLD;

                bit<32> reg = local_metadata.flow_register_number * number_of_switches +
                        local_metadata.switch_register_number ;

                // bit<32> reg_loc = cursor + reg;
                // flow_aggregator.write( reg_loc , data);
                flow_aggregator.write( reg, data);
                cursor = cursor + 1;

                // flow_latency_register.read(flow_latency_value,local_metadata.reg_num);
                // flow_latency_value = flow_latency_value + hdr.int_xd.engress_tstamp - hdr.int_xd.ingress_tstamp;
                // flow_latency_register.write(local_metadata.reg_num,flow_latency_value);


                if (cursor == PACKET_AGGREGATOR_THRESHOLD){

                    hdr.telemetry_header.setValid();

                    hdr.telemetry_header.switch_id = local_metadata.switch_id;
                    hdr.telemetry_header.flow_id = local_metadata.flow_id;
                    hdr.telemetry_header.latency_average = data;


                    // hdr.telemetry_aggregated_header[0].setValid();

                    flow_aggregator.read( data, reg);

                    bit<16> telemetryLength = 96;
                    log_msg("telemetryLength: {} ",{telemetryLength});

                    hdr.ipv4.totalLen  = (bit<16>)IPV4_MIN_HEAD_LEN +
                            (bit<16>)UDP_HEADER_LEN + telemetryLength;
                    log_msg("ipTotalLen: {}", {hdr.ipv4.totalLen} );

                    hdr.udp.udp_length = (bit<16>)UDP_HEADER_LEN + telemetryLength;
                    log_msg("udp_length: {}",{hdr.udp.udp_length});

                    cursor = 0;
                    Forwarding.apply(hdr, local_metadata, standard_metadata);
                }
                aggregator_pointer.write(cursor_location, cursor);



            }
        }
    }
}

control MyEgress(inout headers_t hdr,
                 inout local_metadata_t local_metadata,
                 inout standard_metadata_t standard_metadata) {
    apply {}
}


control MyComputeChecksum(inout headers_t  hdr, inout local_metadata_t meta) {
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


V1Switch(
    PacketParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    PacketDeparser()
) main;
