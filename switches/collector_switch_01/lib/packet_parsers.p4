#ifndef __PACKET_PARSER__
#define __PACKET_PARSER__

#include <core.p4>
#include <v1model.p4>


#include "packet_headers.p4"
#include "definitions.p4"

parser PacketParser(
    packet_in packet,
    out headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata ){
        state start {
            packet.extract(hdr.ethernet);
            transition select(hdr.ethernet.ether_type){
                ETH_TYPE_IPV4: parse_ipv4;
                default: accept;
            }
        }
        state parse_ipv4{
            packet.extract(hdr.ipv4);
            transition select(hdr.ipv4.protocol){
                IP_PROTO_UDP: parse_udp;
                default: accept;
            }
        }

        state parse_udp{
            packet.extract(hdr.udp);
            transition accept;

        }

}

control PacketDeparser(packet_out packet, in headers_t hdr ){
    apply{
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);

    }
}

#endif
