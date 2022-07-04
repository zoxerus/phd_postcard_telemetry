#ifndef __SW_ID__
#define __SW_ID__


control SwitchID(inout headers_t hdr,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata){
    action set_sw_register(bit<32>sw_reg){
        local_metadata.switch_register_number = sw_reg;
    }

    table sw_register {
        key = {
            hdr.ipfix_postcard.ipfix_header.observation_domain : exact;
        }
        actions = {
            NoAction;
            set_sw_register;
        }
    }
    apply{
        sw_register.apply();
    }

}



#endif
