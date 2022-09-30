#include <core.p4>
#incldue <v1model.p4>

#include "lib/packet_parsers.p4"
#include "tables/ipv4_lpm.p4"
#include "lib/packet_headers.p4"
#include "tables/int_xd.p4"
#include "tables/switch_id.p4"

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

        const bit<32> number_of_switches = 3;

        // create a register array to save the telemetry data
        // use the length of the telemetry enteries to set the register size inside <>
        // and array length in between ()
        register <bit<IPFIX_AGG_RECORD_LEN_BITS>> (PACKET_AGGREGATOR_THRESHOLD * number_of_switches) packet_aggregator;

        // a single register to hold the pointer location
        // the pointer points to the last register in the register array that was written to
        register <bit<32>> (number_of_switches) aggregator_pointer;

        register <bit<32>> (1) register_seq_num;


        // a variable to store the value of the pointer
        bit <32> cursor = 0;
        bit <32> seq_num = 0;

        apply {
            if ( hdr.ipv4.isValid() ){

                SwitchID.apply(hdr, local_metadata, standard_metadata);

                // if packet is a postcard then apply postcard processing
                // else just forward the packet to the next hop
                if( local_metadata.is_postcard == 1){

                    // read the value of cursor which points to the
                    // next empty register in the register array
                    aggregator_pointer.read(cursor, local_metadata.switch_register_number);

                    // concatinate header fields and store the resulting value
                    // at the register indicated by cursor

                    bit<IPFIX_AGG_RECORD_LEN_BITS> data =
                            hdr.ipfix_postcard_record.flow_id           ++
                            hdr.ipfix_postcard_record.ttl               ++
                            hdr.ipfix_postcard_record.ingress_tstamp    ++
                            hdr.ipfix_postcard_record.egress_tstamp     ++
                            hdr.ipfix_postcard_record.deq_depth         ++
                            hdr.ipfix_postcard_record.enq_depth         ++
                            hdr.ipfix_postcard_record.ingress_interface ++
                            hdr.ipfix_postcard_record.egress_interface  ++
                            hdr.ipfix_postcard_head.observation_domain  ++
                            hdr.ipfix_postcard_head.export_time         ++
                            hdr.ipfix_postcard_head.sequence_number;

                    // store the data in the aggregator register
                    bit <32> pointer =
                        PACKET_AGGREGATOR_THRESHOLD *
                            local_metadata.switch_register_number + cursor;
                    packet_aggregator.write(pointer, data);

                    // increase the index by one to point to the next register
                    // in the array and check if the register is fulll
                    cursor = cursor + 1;

                    // the language doesnot provide recurrent processing so steps
                    // must be repeated manually
                    // check if threshold is reached
                    // Aggregator threshold is defined in /lib/definitions.p4
                    if (cursor >= PACKET_AGGREGATOR_THRESHOLD ){
                        bit<32> shift = PACKET_AGGREGATOR_THRESHOLD *
                            local_metadata.switch_register_number;
                        register_seq_num.read(seq_num,0);
                        seq_num = seq_num + 1;

                        hdr.ipfix_postcard_head.message_length = IPFIX_AGG_LEN;
                        hdr.ipfix_postcard_head.export_time =
                            (bit<32>)standard_metadata.egress_global_timestamp;
                        hdr.ipfix_postcard_head.sequence_number = seq_num;
                        hdr.ipfix_postcard_head.observation_domain = 0x0a00000b;
                        hdr.ipfix_postcard_set.set_id = 10256;
                        hdr.ipfix_postcard_set.set_length = SET_AGG_LEN;

                        // hdr.ipfix_agg.setValid();
                        // for the lack of recurrent loops in P4 we have
                        // to do this manually :(
                        // set the relevant header fields to valid
                        hdr.ipfix_agg_records[0].setValid();
                        hdr.ipfix_agg_records[1].setValid();
                        hdr.ipfix_agg_records[2].setValid();
                        hdr.ipfix_agg_records[3].setValid();
                        hdr.ipfix_agg_records[4].setValid();
                        hdr.ipfix_agg_records[5].setValid();
                        hdr.ipfix_agg_records[6].setValid();
                        hdr.ipfix_agg_records[7].setValid();
                        hdr.ipfix_agg_records[8].setValid();
                        hdr.ipfix_agg_records[9].setValid();
                        hdr.ipfix_agg_records[10].setValid();
                        hdr.ipfix_agg_records[11].setValid();
                        hdr.ipfix_agg_records[12].setValid();
                        hdr.ipfix_agg_records[13].setValid();
                        hdr.ipfix_agg_records[14].setValid();
                        hdr.ipfix_agg_records[15].setValid();


                        // read data from registers and store them in the relevant
                        // header fields
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[0].one_field, 0 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[1].one_field, 1 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[2].one_field, 2 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[3].one_field, 3 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[4].one_field, 4 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[5].one_field, 5 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[6].one_field, 6 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[7].one_field, 7 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[8].one_field, 8 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[9].one_field, 9 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[10].one_field, 10 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[11].one_field, 11 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[12].one_field, 12 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[13].one_field, 13 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[14].one_field, 14 + shift);
                        packet_aggregator.read(
                            hdr.ipfix_agg_records[15].one_field, 15 + shift);



                        // apply relevant fields to packet headers and forward on egress interface
                        ExportData.apply(hdr,local_metadata,standard_metadata);

                        // reset the aggregator counter
                        cursor = 0;
                    }
                    // store the value of cursor in the relevant register
                    aggregator_pointer.write(local_metadata.
                        switch_register_number,cursor);
                    register_seq_num.write(0,seq_num);
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
