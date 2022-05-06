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
    apply {
        if ( hdr.ipv4.isValid() ){
            // use a match table to check the destination IP and port in order to
            // determine whether this packet is a telemetry postcard
            PostcardDetect.apply(hdr, local_metadata, standard_metadata);
            // if packet is a postcard then apply postcard processing
            // else just forward the packet to the next hop
            if( local_metadata.is_postcard == 1){
                Forwarding.apply(hdr, local_metadata, standard_metadata);
            }
        }
    }
}

control MyEgress(inout headers_t hdr,
                 inout local_metadata_t local_metadata,
                 inout standard_metadata_t standard_metadata) {
    apply {

        log_msg("latency: {} ms",
        { ( standard_metadata.egress_global_timestamp -
            standard_metadata.ingress_global_timestamp ) } );
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
