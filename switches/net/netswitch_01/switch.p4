
#include "lib/packet_parsers.p4"
#include "tables/ipv4_lpm.p4"
#include "tables/int_xd.p4"
#include "lib/utils.p4"
#include "tables/telemetry_acl.p4"


control MyVerifyChecksum(inout headers_t hdr, inout local_metadata_t meta) {
    apply {  }
}

control MyIngress (
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata){
        apply {
            if ( hdr.ipv4.isValid() ){
                // apply normal forwarding
                Forwarding.apply(hdr, local_metadata, standard_metadata);
                // check the telemetry ACL table to see if the packet should be cloned
                TelemetryACL.apply(hdr, local_metadata, standard_metadata);

            }
        }
}

control MyEgress(inout headers_t hdr,
                 inout local_metadata_t local_metadata,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // check if the packet is a clone and apply the clone processing.
        if (IS_E2E_CLONE( standard_metadata ) ) {
            ExportData.apply(hdr, local_metadata, standard_metadata );
        } else {
            // if the queue depthe is bigger than a threshold then set the TOS field
            // in the IP header to inform the receiver
            if ( standard_metadata.enq_qdepth > 5 ){
                hdr.ipv4.diffserv = 0b00000011;
            }
            // check if the local_metadata indicate whether the packet must be cloned
            // this bit is set in the ingress control TelemetryACL.
            if ( ( local_metadata.mark_to_clone == 1 ) ){
                // if packet needs to be cloned for telemetry then add the relevant
                // telemetry data to the local_metadate and clone the packet
                // thecloned pakcet adds an extra header that contains the telemetry date
                local_metadata.ingress_tstamp = (bit<32>)standard_metadata.ingress_global_timestamp;
                local_metadata.egress_tstamp =  (bit<32>)standard_metadata.egress_global_timestamp ;
               //  local_metadata.enq_qdepth = (bit<24>)standard_metadata.enq_qdepth;
               //  local_metadata.deq_qdepth = (bit<24>)standard_metadata.deq_qdepth;
               // hash(local_metadata.flow_id, HashAlgorithm.crc16, (bit<32>)0,{
               //    hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.src_port,
               //    hdr.udp.dst_port, hdr.tcp.src_port, hdr.tcp.dst_port,
               //    hdr.ipv4.protocol}, (bit<32>)4294967295);
                 clone_preserving_field_list(CloneType.E2E, 500, 1);
            }
        }
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


    	update_checksum(
    	    hdr.xd_ipv4.isValid(),
                { hdr.xd_ipv4.version,
    	      hdr.xd_ipv4.ihl,
                  hdr.xd_ipv4.diffserv,
                  hdr.xd_ipv4.totalLen,
                  hdr.xd_ipv4.identification,
                  hdr.xd_ipv4.flags,
                  hdr.xd_ipv4.fragOffset,
                  hdr.xd_ipv4.ttl,
                  hdr.xd_ipv4.protocol,
                  hdr.xd_ipv4.src_addr,
                  hdr.xd_ipv4.dst_addr },
                hdr.xd_ipv4.hdrChecksum,
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
