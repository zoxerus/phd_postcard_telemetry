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

    // the memory is organized in banks, each bank stores the data of one switch
    // each bank is divided into vaults, where each vault stores data of one
    // flow. each vault has a number N compartments, where N is the aggregation
    // level, in other words N is the number of postcards that are aggregated
    // and summarized. each compartment has a number of drawers equal to the
    // number of variables that the switch stores, e.g. latency.
    // or in other words, it's a 3D array where the row represents the switch
    // and the column represents the flow number, and the depth represent the
    // variable.
    //
    // aggregator_pointer stores the location of the last compartment that we
    // have written to in this switch and for this flow.
    register <bit<8>>  (totalSize) aggregator_pointer;

    // register_*_max is a 2D array (switch,flow) where each cell of this
    // 2D array is updated with the max value if the last value received for
    // variable is higher than the stored one. same logic is for
    // register_*_. while register_*_sum stores the sum of
    // variables for them to later be divided by N (the number of aggregated
    // packets)
    register <bit<48>> (totalSize) register_latency_max;
    register <bit<48>> (totalSize) register_latency_min;
    register <bit<48>> (totalSize) register_latency_sum;

    register <bit<24>> (totalSize) register_enq_max;
    register <bit<24>> (totalSize) register_enq_min;
    register <bit<24>> (totalSize) register_enq_sum;

    register <bit<24>> (totalSize) register_deq_min;
    register <bit<24>> (totalSize) register_deq_max;
    register <bit<24>> (totalSize) register_deq_sum;

    // variables with descriptive names
    bit <8>  cursor = 0;
    bit <48> max_latency;
    bit <48> min_latency;
    bit <48> sum_latency;

    bit<24> max_enq;
    bit<24> min_enq;
    bit<24> sum_enq;

    bit<24> max_deq;
    bit<24> min_deq;
    bit<24> sum_deq;
    apply {
        if ( hdr.ipv4.isValid() ){
            // use a match table to check the destination IP and port in order
            // to determine whether this packet is a telemetry postcard
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
                bit<48> latency = ( hdr.ipfix_postcard.record.egress_tstamp -
                    hdr.ipfix_postcard.record.ingress_tstamp );

                // if this is the first packet in the aggregation then we store
                // the valeus of the parameters, otherwise we compare with the
                // already stored values
                if (cursor == 0){
                    register_latency_max.write(pointer, latency);
                    register_latency_min.write(pointer, latency);
                    register_latency_sum.write(pointer, latency);

                    register_enq_min.write(pointer,
                            hdr.ipfix_postcard.record.enq_depth);
                    register_enq_max.write(pointer,
                            hdr.ipfix_postcard.record.enq_depth);
                    register_enq_sum.write(pointer,
                            hdr.ipfix_postcard.record.enq_depth);

                    register_deq_min.write(pointer,
                            hdr.ipfix_postcard.record.deq_depth);
                    register_deq_max.write(pointer,
                            hdr.ipfix_postcard.record.deq_depth);
                    register_deq_sum.write(pointer,
                            hdr.ipfix_postcard.record.deq_depth);

                } else {
                    // variables with descriptive names.
                    bit<48> old_latency;
                    bit<48> new_latency;

                    bit<24> old_enq;
                    bit<24> new_enq;

                    bit<24> old_deq;
                    bit<24> new_deq;

                    // read values from registers and store them in relevant
                    // variables
                    register_latency_sum.read(old_latency, pointer);
                    register_latency_max.read(max_latency, pointer);
                    register_latency_min.read(min_latency, pointer);

                    register_enq_sum.read(old_enq, pointer);
                    register_enq_max.read(max_enq, pointer);
                    register_enq_min.read(min_enq, pointer);

                    register_deq_sum.read(old_deq, pointer);
                    register_deq_max.read(max_deq, pointer);
                    register_deq_min.read(min_deq, pointer);

                    // update the variables with new values.
                    new_latency = old_latency + latency;
                    new_enq = old_enq + hdr.ipfix_postcard.record.enq_depth;
                    new_deq = old_deq + hdr.ipfix_postcard.record.deq_depth;


                    // store the variables in the registers.
                    register_latency_sum.write(pointer, new_latency);
                    register_enq_sum.write(pointer, new_enq);
                    register_deq_sum.write(pointer, new_deq);

                    // compare old and new values for the max and min variables
                    if (latency < min_latency){
                        register_latency_min.write(pointer, latency);
                    }
                    if (latency > max_latency){
                        register_latency_max.write(pointer, latency);
                    }

                    if (hdr.ipfix_postcard.record.enq_depth < min_enq){
                        register_enq_min.write(pointer,
                                hdr.ipfix_postcard.record.enq_depth);
                    }
                    if (hdr.ipfix_postcard.record.enq_depth > max_enq){
                        register_enq_max.write(pointer,
                                hdr.ipfix_postcard.record.enq_depth);
                    }


                    if (hdr.ipfix_postcard.record.deq_depth < min_deq){
                        register_deq_min.write(pointer,
                                hdr.ipfix_postcard.record.deq_depth);
                    }
                    if (hdr.ipfix_postcard.record.deq_depth > max_deq){
                        register_deq_max.write(pointer,
                                hdr.ipfix_postcard.record.deq_depth);
                    }



                }
                // increase cursor by 1 and check if threshold is reached
                cursor = cursor + 1;

                // if threshold is reached then send the aggregated or
                // summerized packet from the total of postcards.
                if (cursor == PACKET_AGGREGATOR_THRESHOLD){
                    // activate teh ipfix_sum header for it to be included in
                    // the output packet by the parser.
                    hdr.ipfix_sum.setValid();

                    // set the values for the ipfix header.
                    hdr.ipfix_sum.ipfix_header.version_number = 10;
                    hdr.ipfix_sum.ipfix_header.message_length = IPFIX_SUM_LEN;
                    hdr.ipfix_sum.ipfix_header.export_time =
                        (bit<32>)standard_metadata.ingress_global_timestamp;

                    // TODO: implement sequence numbers
                    hdr.ipfix_sum.ipfix_header.sequence_number = 99;
                    hdr.ipfix_sum.ipfix_header.observation_domain =
                        local_metadata.switch_id;

                    hdr.ipfix_sum.set.set_id = SET_SUM_ID;
                    hdr.ipfix_sum.set.set_length = SET_SUM_LEN;

                    // TODO: moves the collector_id to be set by the controll
                    // plane
                    hdr.ipfix_sum.record.collector_id = 0x01010101;
                    hdr.ipfix_sum.record.flow_id = local_metadata.flow_id;

                    register_latency_min.read(min_latency, pointer);
                    hdr.ipfix_sum.record.latency_min = min_latency;

                    register_latency_max.read(max_latency, pointer);
                    hdr.ipfix_sum.record.latency_max = max_latency;

                    register_latency_sum.read(sum_latency, pointer);
                    hdr.ipfix_sum.record.latency_avg =
                        sum_latency/PACKET_AGGREGATOR_THRESHOLD;


                    register_enq_min.read(min_enq, pointer);
                    hdr.ipfix_sum.record.enq_min = min_enq;
                    register_enq_max.read(max_enq, pointer);
                    hdr.ipfix_sum.record.enq_max = max_enq;
                    register_enq_sum.read(sum_enq, pointer);
                    hdr.ipfix_sum.record.enq_avg =
                        sum_enq/PACKET_AGGREGATOR_THRESHOLD;


                    register_deq_min.read(min_deq, pointer);
                    hdr.ipfix_sum.record.deq_min = min_deq;
                    register_deq_max.read(max_deq, pointer);
                    hdr.ipfix_sum.record.deq_max = max_deq;
                    register_deq_sum.read(sum_deq, pointer);
                    hdr.ipfix_sum.record.deq_avg =
                        sum_deq/PACKET_AGGREGATOR_THRESHOLD;

                    ExportData.apply(hdr,local_metadata, standard_metadata);

                    cursor = 0;
                }
                // sotre the value of cursor in the correct sell of the 2D array
                // for aggregator_pointer.
                aggregator_pointer.write(pointer, cursor);



            }
            // if packet is not a postcard, then just forward it according to
            // it's destination IP address.
            else {
                Forwarding.apply(hdr, local_metadata, standard_metadata);
            }
        }
    }
}

control MyEgress(inout headers_t hdr,
                 inout local_metadata_t local_metadata,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // Empty Egress Processing.
    }
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
