#include <core.p4>
#incldue <v1model.p4>

#include "lib/packet_parsers.p4"
#include "tables/ipv4_lpm.p4"
#include "tables/postcard_detect.p4"
#include "lib/packet_headers.p4"
#include "tables/int_xd.p4"


control MyVerifyChecksum(inout headers_t hdr, inout local_metadata_t meta) {
    apply {  }
}

control MyIngress (
        inout headers_t hdr,
        inout local_metadata_t local_metadata,
        inout standard_metadata_t standard_metadata){

    // the number of flows and switches in the network
    const bit<32> number_of_flows = 4;
    const bit<32> number_of_switches = 3;
    const bit<32> totalSize = number_of_flows * number_of_switches;


    // these are registers used to hold the values for aggregation and correlation
    register <bit<8>>  (totalSize) aggregator_pointer;
    register <bit<32>> (totalSize) register_max_latency;
    register <bit<32>> (totalSize) register_min_latency;
    register <bit<32>> (totalSize) register_act_latency;

    /*
    register <bit<64>> (number_of_switches) register_max_inque;
    register <bit<64>> (number_of_switches) register_min_inque;
    register <bit<64>> (number_of_switches) register_max_eque;
    register <bit<64>> (number_of_switches) register_min_eque;
    */

    // register <bit<32>> (number_of_flows) flow_latency_register;
    // bit<32> flow_latency_value;

    // variables with descriptive names
    bit <8>  cursor = 0;
    bit <32> max_latency;
    bit <32> min_latency;
    bit <32> sum_latency;

    apply {
        if ( hdr.ipv4.isValid() ){

            // use a match table to check the destination IP and port in order to
            // determine whether this packet is a telemetry postcard
            PostcardDetect.apply(hdr, local_metadata, standard_metadata);

            // if packet is a postcard then apply postcard processing
            // else just forward the packet to the next hop
            if( local_metadata.is_postcard == 1){
                // we use sw_ord (switch order) and fl_ord (flow order)
                // as a short nickname for the righthand side
                bit<32> sw_ord = local_metadata.switch_register_number;
                bit<32> fl_ord = local_metadata.flow_register_number;


                // a variable to point for the correct register calculated from
                // switch order, flow order, and the number of flows
                bit<32> pointer = (sw_ord * number_of_flows) + fl_ord;

                // read the correct cursor value for the current flow and switch
                aggregator_pointer.read(cursor, pointer);


                // calculate the latency of the current postcard from
                // the values included in the headers
                bit<32> latency = ( hdr.int_xd.engress_tstamp -
                    hdr.int_xd.ingress_tstamp );


                // if this is the first packet in the aggregation then we store the valeus
                // of the parameters, otherwise we compare with the already stored values
                if (cursor == 0){
                    register_max_latency.write(pointer, latency);
                    register_min_latency.write(pointer, latency);
                    register_act_latency.write(pointer, latency);

                } else {
                    bit<32> old_latency;
                    bit<32> new_latency;

                    register_act_latency.read(old_latency, pointer);
                    register_max_latency.read(max_latency, pointer);
                    register_min_latency.read(min_latency, pointer);

                    new_latency = old_latency + latency;
                    register_act_latency.write(pointer, new_latency);

                    if (latency < min_latency){
                        register_min_latency.write(pointer, latency);
                    }
                    if (latency > max_latency){
                        register_max_latency.write(pointer, latency);
                    }

                }
                // increase cursor by 1 and check if threshold is reached
                cursor = cursor + 1;

                if (cursor == PACKET_AGGREGATOR_THRESHOLD){
                    log_msg("preparing aggregated packet");

                    hdr.telemetry_header.setValid();
                    hdr.telemetry_header.sum_of = (bit<8>) cursor;
                    hdr.telemetry_header.switch_id = local_metadata.switch_id;
                    hdr.telemetry_header.flow_id = local_metadata.flow_id;

                    register_min_latency.read(min_latency, pointer);
                    hdr.telemetry_header.min_latency = min_latency;

                    register_max_latency.read(max_latency, pointer);
                    hdr.telemetry_header.max_latency = max_latency;

                    register_act_latency.read(sum_latency, pointer);
                    hdr.telemetry_header.avg_latency = sum_latency/PACKET_AGGREGATOR_THRESHOLD;

                    ExportData.apply(hdr,local_metadata, standard_metadata);

                    cursor = 0;
                }
                aggregator_pointer.write(pointer, cursor);



            } else {
                Forwarding.apply(hdr, local_metadata, standard_metadata);
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
                   hdr.ipv4.src_addr,
                   hdr.ipv4.dst_addr },
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
