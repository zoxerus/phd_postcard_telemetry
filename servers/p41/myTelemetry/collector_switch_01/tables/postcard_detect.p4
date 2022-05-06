#ifndef __POSTCARD_DETECT__
#define __POSTCARD_DETECT__


control PostcardDetect(
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata){

    action set_postcard_bit(){
        local_metadata.is_postcard = 1;
    }

    table table_detect_postcard{
        key = {
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dst_port: exact;
        }
        actions = {
            NoAction;
            set_postcard_bit;
        }
    }

    apply{
        table_detect_postcard.apply();
    }

}

#endif
