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
        // create a register array to save the telemetry data
        // use the length of the telemetry enteries to set the register size inside << >>
        // and array length in between ()
        register <bit<REPORT_FIXED_HEADER_LEN>>(PACKET_AGGREGATOR_THRESHOLD)packet_aggregator ;
        // a single register to hold the pointer location
        // the pointer points to the last register in the register array that was written to
        register <bit<32>>(1)aggregator_pointer;
        // a variable to store the value of the pointer
        bit <32> cursor;
        apply {

            if ( hdr.ipv4.isValid() ){
                // use a match table to check the destination IP and port in order to
                // determine whether this packet is a telemetry postcard
                PostcardDetect.apply(hdr, local_metadata, standard_metadata);
                // if packet is a postcard then apply postcard processing
                // else just forward the packet to the next hop
                if( local_metadata.is_postcard == 1){
                    log_msg("postcard received");

                    // read the value of cursor which is the
                    // last index at which a packet was stored
                    aggregator_pointer.read(cursor, 0);
                    // store telemetry headers at the next index indicated by cursor
                    bit<REPORT_FIXED_HEADER_LEN> data = hdr.int_xd.ver ++
                                                        hdr.int_xd.len ++
                                                        hdr.int_xd.nproto ++
                                                        hdr.int_xd.rep_md_bits ++
                                                        hdr.int_xd.d ++
                                                        hdr.int_xd.q ++
                                                        hdr.int_xd.f ++
                                                        hdr.int_xd.rsvd ++
                                                        hdr.int_xd.hw_id ++
                                                        hdr.int_xd.sw_id ++
                                                        hdr.int_xd.seq_no ++
                                                        hdr.int_xd.ingress_tstamp ++
                                                        hdr.int_xd.engress_tstamp;

                    packet_aggregator.write((bit<32>)cursor, data);

                    // increase the index by one to point to the next register
                    // in the array and check if the register is fulll
                    cursor = cursor + 1;
                    // the language doesnot provide recurrent processing so steps
                    // must be repeated manually
                    // Aggregator threshold is 50 defined in /lib/definitions.p4
                    if (cursor >= PACKET_AGGREGATOR_THRESHOLD ){
                        hdr.telemetry_aggregated_header[0].setValid();
                        hdr.telemetry_aggregated_header[1].setValid();
                        hdr.telemetry_aggregated_header[2].setValid();
                        hdr.telemetry_aggregated_header[3].setValid();
                        hdr.telemetry_aggregated_header[4].setValid();
                        hdr.telemetry_aggregated_header[5].setValid();
                        hdr.telemetry_aggregated_header[6].setValid();
                        hdr.telemetry_aggregated_header[7].setValid();
                        hdr.telemetry_aggregated_header[8].setValid();
                        hdr.telemetry_aggregated_header[9].setValid();
                        hdr.telemetry_aggregated_header[10].setValid();
                        hdr.telemetry_aggregated_header[11].setValid();
                        hdr.telemetry_aggregated_header[12].setValid();
                        hdr.telemetry_aggregated_header[13].setValid();
                        hdr.telemetry_aggregated_header[14].setValid();


                        packet_aggregator.read( hdr.telemetry_aggregated_header[0].one_field, 0);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[1].one_field, 1);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[2].one_field, 2);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[3].one_field, 3);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[4].one_field, 4);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[5].one_field, 5);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[6].one_field, 6);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[7].one_field, 7);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[8].one_field, 8);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[9].one_field, 9);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[10].one_field, 10);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[11].one_field, 11);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[12].one_field, 12);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[13].one_field, 13);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[14].one_field, 14);


                        bit<16> telemetryLength = (bit<16>)REPORT_FIXED_HEADER_LEN * (bit<16>)PACKET_AGGREGATOR_THRESHOLD;

                        hdr.ipv4.totalLen  = (bit<16>)IPV4_MIN_HEAD_LEN +
                                (bit<16>)UDP_HEADER_LEN + telemetryLength;

                        hdr.udp.udp_length = (bit<16>)UDP_HEADER_LEN + telemetryLength;

                        cursor = 0;
                        Forwarding.apply(hdr, local_metadata, standard_metadata);
                    }
                    aggregator_pointer.write(0,cursor);
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
