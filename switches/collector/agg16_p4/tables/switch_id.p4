#ifndef __SW_ID__
#define __SW_ID__


control SwitchID(inout headers_t hdr,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata){
    action select_switch_register(bit<32>sw_reg){
        local_metadata.switch_register_number = sw_reg;
        log_msg("sw_reg: {}",{sw_reg});
    }

    table table_detect_switch {
        key = {
            hdr.group_header.node_id : exact;
        }
        actions = {
            NoAction;
            select_switch_register;
        }
    }
    apply{
        table_detect_switch.apply();
    }

}



#endif
