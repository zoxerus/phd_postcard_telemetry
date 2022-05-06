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

    //register <bit<AGGREGATION_POSTCARD_LEN_BITS>> (PACKET_AGGREGATOR_THRESHOLD)packet_aggregator;
    register <bit<48>> (totalSize) register_latency_max;
    register <bit<48>> (totalSize) register_latency_min;
    register <bit<48>> (totalSize) register_latency_sum;

    register <bit<19>> (totalSize) register_enq_max;
    register <bit<19>> (totalSize) register_enq_min;
    register <bit<19>> (totalSize) register_enq_sum;

    register <bit<19>> (totalSize) register_deq_min;
    register <bit<19>> (totalSize) register_deq_max;
    register <bit<19>> (totalSize) register_deq_sum;

    // variables with descriptive names
    bit <8>  cursor = 0;
    bit <48> max_latency;
    bit <48> min_latency;
    bit <48> sum_latency;

    bit<19> max_enq;
    bit<19> min_enq;
    bit<19> sum_enq;

    bit<19> max_deq;
    bit<19> min_deq;
    bit<19> sum_deq;
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
                bit<48> latency = ( hdr.postcard.egress_tstamp -
                    hdr.postcard.ingress_tstamp );

                // if this is the first packet in the aggregation then we store the valeus
                // of the parameters, otherwise we compare with the already stored values
                if (cursor == 0){
                    register_latency_max.write(pointer, latency);
                    register_latency_min.write(pointer, latency);
                    register_latency_sum.write(pointer, latency);

                    register_enq_min.write(pointer, hdr.postcard.enq_depth);
                    register_enq_max.write(pointer, hdr.postcard.enq_depth);
                    register_enq_sum.write(pointer, hdr.postcard.enq_depth);

                    register_deq_min.write(pointer, hdr.postcard.deq_depth);
                    register_deq_max.write(pointer, hdr.postcard.deq_depth);
                    register_deq_sum.write(pointer, hdr.postcard.deq_depth);

                } else {
                    bit<48> old_latency;
                    bit<48> new_latency;

                    bit<19> old_enq;
                    bit<19> new_enq;

                    bit<19> old_deq;
                    bit<19> new_deq;

                    register_latency_sum.read(old_latency, pointer);
                    register_latency_max.read(max_latency, pointer);
                    register_latency_min.read(min_latency, pointer);

                    register_enq_sum.read(old_enq, pointer);
                    register_enq_max.read(max_enq, pointer);
                    register_enq_min.read(min_enq, pointer);

                    register_deq_sum.read(old_deq, pointer);
                    register_deq_max.read(max_deq, pointer);
                    register_deq_min.read(min_deq, pointer);

                    new_latency = old_latency + latency;
                    new_enq = old_enq + hdr.postcard.enq_depth;
                    new_deq = old_deq + hdr.postcard.deq_depth;

                    register_latency_sum.write(pointer, new_latency);
                    register_enq_sum.write(pointer, new_enq);
                    register_deq_sum.write(pointer, new_deq);

                    if (latency < min_latency){
                        register_latency_min.write(pointer, latency);
                    }
                    if (latency > max_latency){
                        register_latency_max.write(pointer, latency);
                    }

                    if (hdr.postcard.enq_depth < min_enq){
                        register_enq_min.write(pointer, hdr.postcard.enq_depth);
                    }
                    if (hdr.postcard.enq_depth > max_enq){
                        register_enq_max.write(pointer, hdr.postcard.enq_depth);
                    }


                    if (hdr.postcard.deq_depth < min_deq){
                        register_deq_min.write(pointer, hdr.postcard.deq_depth);
                    }
                    if (hdr.postcard.deq_depth > max_deq){
                        register_deq_max.write(pointer, hdr.postcard.deq_depth);
                    }



                }
                // increase cursor by 1 and check if threshold is reached
                cursor = cursor + 1;

                if (cursor == PACKET_AGGREGATOR_THRESHOLD){
                    log_msg("preparing aggregated packet");

                    hdr.telemetry_sum.setValid();
                    hdr.telemetry_sum.sum_of = (bit<6>) cursor;
                    hdr.telemetry_sum.switch_id = local_metadata.switch_id;
                    hdr.telemetry_sum.flow_id = local_metadata.flow_id;

                    register_latency_min.read(min_latency, pointer);
                    hdr.telemetry_sum.latency_min = min_latency;

                    register_latency_max.read(max_latency, pointer);
                    hdr.telemetry_sum.latency_max = max_latency;

                    register_latency_sum.read(sum_latency, pointer);
                    hdr.telemetry_sum.latency_avg = sum_latency/PACKET_AGGREGATOR_THRESHOLD;


                    register_enq_min.read(min_enq, pointer);
                    hdr.telemetry_sum.enq_min = min_enq;
                    register_enq_max.read(max_enq, pointer);
                    hdr.telemetry_sum.enq_max = max_enq;
                    register_enq_sum.read(sum_enq, pointer);
                    hdr.telemetry_sum.enq_avg = sum_enq/PACKET_AGGREGATOR_THRESHOLD;


                    register_deq_min.read(min_deq, pointer);
                    hdr.telemetry_sum.deq_min = min_deq;
                    register_deq_max.read(max_deq, pointer);
                    hdr.telemetry_sum.deq_max = max_deq;
                    register_deq_sum.read(sum_deq, pointer);
                    hdr.telemetry_sum.deq_avg = sum_deq/PACKET_AGGREGATOR_THRESHOLD;

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
