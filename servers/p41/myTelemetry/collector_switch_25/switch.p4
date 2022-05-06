#include <core.p4>
#incldue <v1model.p4>

#include "lib/packet_parsers.p4"
#include "tables/ipv4_lpm.p4"
#include "tables/postcard_detect.p4"
#include "lib/packet_headers.p4"
#include "lib/utils.p4"
#include "tables/int_xd.p4"


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
        register <bit<REPORT_FIXED_HEADER_LEN_BITS>>(PACKET_AGGREGATOR_THRESHOLD)packet_aggregator ;
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
                    // read the value of cursor which is the
                    // last index at which a packet was stored
                    aggregator_pointer.read(cursor, 0);

                    // store telemetry headers at the next index indicated by cursor
                    bit<REPORT_FIXED_HEADER_LEN_BITS> data = hdr.int_xd.ver ++
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
                        hdr.telemetry_aggregated_header[15].setValid();
                        hdr.telemetry_aggregated_header[16].setValid();
                        hdr.telemetry_aggregated_header[17].setValid();
                        hdr.telemetry_aggregated_header[18].setValid();
                        hdr.telemetry_aggregated_header[19].setValid();
                        hdr.telemetry_aggregated_header[20].setValid();
                        hdr.telemetry_aggregated_header[21].setValid();
                        hdr.telemetry_aggregated_header[22].setValid();
                        hdr.telemetry_aggregated_header[23].setValid();
                        hdr.telemetry_aggregated_header[24].setValid();
                        // hdr.telemetry_aggregated_header[25].setValid();
                        // hdr.telemetry_aggregated_header[26].setValid();
                        // hdr.telemetry_aggregated_header[27].setValid();
                        // hdr.telemetry_aggregated_header[28].setValid();
                        // hdr.telemetry_aggregated_header[29].setValid();
                        // hdr.telemetry_aggregated_header[30].setValid();
                        // hdr.telemetry_aggregated_header[31].setValid();
                        // hdr.telemetry_aggregated_header[32].setValid();
                        // hdr.telemetry_aggregated_header[33].setValid();
                        // hdr.telemetry_aggregated_header[34].setValid();
                        // hdr.telemetry_aggregated_header[35].setValid();
                        // hdr.telemetry_aggregated_header[36].setValid();
                        // hdr.telemetry_aggregated_header[37].setValid();
                        // hdr.telemetry_aggregated_header[38].setValid();
                        // hdr.telemetry_aggregated_header[39].setValid();
                        // hdr.telemetry_aggregated_header[40].setValid();
                        // hdr.telemetry_aggregated_header[41].setValid();
                        // hdr.telemetry_aggregated_header[42].setValid();
                        // hdr.telemetry_aggregated_header[43].setValid();
                        // hdr.telemetry_aggregated_header[44].setValid();
                        // hdr.telemetry_aggregated_header[45].setValid();
                        // hdr.telemetry_aggregated_header[46].setValid();
                        // hdr.telemetry_aggregated_header[47].setValid();
                        // hdr.telemetry_aggregated_header[48].setValid();
                        // hdr.telemetry_aggregated_header[49].setValid();


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
                        packet_aggregator.read( hdr.telemetry_aggregated_header[16].one_field, 16);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[17].one_field, 17);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[18].one_field, 18);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[19].one_field, 19);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[20].one_field, 20);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[21].one_field, 21);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[22].one_field, 22);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[23].one_field, 23);
                        packet_aggregator.read( hdr.telemetry_aggregated_header[24].one_field, 24);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[25].one_field, 25);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[26].one_field, 26);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[27].one_field, 27);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[28].one_field, 28);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[29].one_field, 29);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[30].one_field, 30);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[31].one_field, 31);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[32].one_field, 32);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[33].one_field, 33);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[34].one_field, 34);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[35].one_field, 35);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[36].one_field, 36);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[37].one_field, 37);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[38].one_field, 38);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[39].one_field, 39);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[40].one_field, 40);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[41].one_field, 41);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[42].one_field, 42);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[43].one_field, 43);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[44].one_field, 44);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[45].one_field, 45);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[46].one_field, 46);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[47].one_field, 47);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[48].one_field, 48);
                        // packet_aggregator.read( hdr.telemetry_aggregated_header[49].one_field, 49);

                        ExportData.apply(hdr,local_metadata,standard_metadata);
                        // bit<16> telemetryLength = (bit<16>)REPORT_FIXED_HEADER_LEN_BYTES * (bit<16>)PACKET_AGGREGATOR_THRESHOLD;
                        //
                        // hdr.ipv4.totalLen  = (bit<16>)IPV4_MIN_HEAD_LEN +
                        //         (bit<16>)UDP_HEADER_LEN + telemetryLength;
                        //
                        // hdr.udp.udp_length = (bit<16>)UDP_HEADER_LEN + telemetryLength;

                        cursor = 0;
                        // Forwarding.apply(hdr, local_metadata, standard_metadata);
                        // clone(CloneType.I2E,500);
                    }
                    aggregator_pointer.write(0,cursor);
                }
            }
        }
    }

control MyEgress(inout headers_t hdr,
                 inout local_metadata_t local_metadata,
                 inout standard_metadata_t standard_metadata) {
    apply {

        // bit<16> telemetryLength = (bit<16>)REPORT_FIXED_HEADER_LEN_BYTES * (bit<16>)PACKET_AGGREGATOR_THRESHOLD;
        //
        // hdr.ipv4.totalLen  = (bit<16>)IPV4_MIN_HEAD_LEN +
        //         (bit<16>)UDP_HEADER_LEN + telemetryLength;
        //
        // hdr.udp.udp_length = (bit<16>)UDP_HEADER_LEN + telemetryLength;

        if(IS_I2E_CLONE( standard_metadata )){
            // Forwarding.apply(hdr,local_metadata, standard_metadata);
        }
        // if (local_metadata.is_forwarded == 1){
        //     bit<48> intst;
        //     ingress_tstamp.read(intst,0);
        //     log_msg("delay: {}",{(standard_metadata.egress_global_timestamp - intst)});
        // }

    }
}


control MyComputeChecksum(inout headers_t  hdr, inout local_metadata_t meta) {
     apply {
	update_checksum(
	    hdr.xd_ip_header.isValid(),
            { hdr.xd_ip_header.version,
	      hdr.xd_ip_header.ihl,
              hdr.xd_ip_header.diffserv,
              hdr.xd_ip_header.totalLen,
              hdr.xd_ip_header.identification,
              hdr.xd_ip_header.flags,
              hdr.xd_ip_header.fragOffset,
              hdr.xd_ip_header.ttl,
              hdr.xd_ip_header.protocol,
              hdr.xd_ip_header.srcAddr,
              hdr.xd_ip_header.dstAddr },
            hdr.xd_ip_header.hdrChecksum,
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
