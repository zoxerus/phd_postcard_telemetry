#include <core.p4>
#incldue <v1model.p4>

#include "lib/packet_parsers.p4"
#include "tables/ipv4_lpm.p4"
#include "lib/packet_headers.p4"
#include "tables/int_xd.p4"

/*
########################## How it Works ##########################
1. When a packet is received the parser checks the destination IP address and
        UDP port number to determine if it's a postcard (telemetry packet) and
        sets a relevant flag in the local_metadata defined by the user.

2. if it's a postcard then the parser goes to parse_postcard_header state to
        extract the telemetry header.

3. at the ingress if the flag is_postcard is set then the telemetry data is
        stored in memory and a counter is increased up to a limit.

4. when the counter reaches the specified limit, data is retrieved from the
        memory and aggregated in one packet and forwarded to telemetry server

*/

control MyVerifyChecksum(inout headers_t hdr, inout local_metadata_t meta) {
    apply {  }
}

control MyIngress (
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata){

        // create a register array to save the telemetry data
        // use the length of the telemetry enteries to set the register size inside <>
        // and array length in between ()
        register <bit<REPORT_FIXED_HEADER_LEN_BITS>>(PACKET_AGGREGATOR_THRESHOLD)packet_aggregator ;

        // a single register to hold the pointer location
        // the pointer points to the last register in the register array that was written to
        register <bit<32>>(1)aggregator_pointer;

        // a variable to store the value of the pointer
        bit <32> cursor;

        apply {
            if ( hdr.ipv4.isValid() ){
                // if packet is a postcard then apply postcard processing
                // else just forward the packet to the next hop
                if( local_metadata.is_postcard == 1){
                    log_msg("postcard detected");
                    // read the value of cursor which points to the
                    // next empty register in the register array
                    aggregator_pointer.read(cursor, 0);

                    // concatinate header fields and store the resulting value
                    // at the register indicated by cursor
                    bit<REPORT_FIXED_HEADER_LEN_BITS> data = hdr.int_xd.switch_id ++
                                                        hdr.int_xd.flow_id ++
                                                        hdr.int_xd.ttl ++
                                                        hdr.int_xd.ingress_tstamp ++
                                                        hdr.int_xd.egress_tstamp ++
                                                        hdr.int_xd.deq_depth ++
                                                        hdr.int_xd.enq_depth ++
                                                        hdr.int_xd.ingress_port ++
                                                        hdr.int_xd.egress_port;

                    // store the data in the aggregator register
                    packet_aggregator.write((bit<32>)cursor, data);

                    // increase the index by one to point to the next register
                    // in the array and check if the register is fulll
                    cursor = cursor + 1;

                    // the language doesnot provide recurrent processing so steps
                    // must be repeated manually
                    // check if threshold is reached
                    // Aggregator threshold is defined in /lib/definitions.p4
                    if (cursor >= PACKET_AGGREGATOR_THRESHOLD ){
                        // for the lack of recurrent loops in P4 we have
                        // to do this manually :(
                        // set the relevant header fields to valid
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
                        hdr.telemetry_aggregated_header[15].setValid();


                        // read data from registers and store them in the relevant
                        // header fields
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
                        packet_aggregator.read( hdr.telemetry_aggregated_header[15].one_field, 15);



                        // apply relevant fields to packet headers and forward on egress interface
                        ExportData.apply(hdr,local_metadata,standard_metadata);

                        // reset the aggregator counter
                        cursor = 0;
                    }
                    // store the value of cursor in the relevant register
                    aggregator_pointer.write(0,cursor);
                } else {
                    // if packet is not a postcard, just forward it normally
                    Forwarding.apply(hdr, local_metadata, standard_metadata);
                }
            }
        }
    }

control MyEgress(inout headers_t hdr,
                 inout local_metadata_t local_metadata,
                 inout standard_metadata_t standard_metadata) {
    apply { /* empty egress */ }
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
