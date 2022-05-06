#ifndef __TELEMETRY_ACL__
#def __TELEMETRY_ACL__


control TelemetryACL(
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata ){

    action clone_to_collector(){
        local_metadata.mark_to_clone = 1;
        local_metadata.ttl = hdr.ipv4.ttl;
        return;
    }


    table table_int_srcip {
        key = {
            hdr.ipv4.src_addr: lpm;
        }
        actions = {
            clone_to_collector;
            NoAction;
        }
        const default_action = NoAction();
    }

    table table_int_dstip {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            clone_to_collector;
            NoAction;
        }
        const default_action = NoAction();
    }

    table table_int_srcudp {
        key = {
            hdr.udp.src_port: range;
        }
        actions = {
            clone_to_collector;
            NoAction;
        }
        const default_action = NoAction();
    }

    table table_int_dstudp {
        key = {
            hdr.udp.dst_port: range;
        }
        actions = {
            clone_to_collector;
            NoAction;
        }
        const default_action = NoAction();
    }

    apply{
        table_int_srcip.apply();
        table_int_dstip.apply();
        table_int_srcudp.apply();
        table_int_dstudp.apply();
    }


}


#endif
