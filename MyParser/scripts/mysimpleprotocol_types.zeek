module MYSIMPLEPROTOCOL;

export {
    type general_log: record {
        ts                              : time &log;
        uid                             : string &log;
        id                              : conn_id &log;
        proto                           : string &log;
        body_data                       : vector of count &log &optional;
        header_header_bits_version      : count &log &optional;
        header_header_bits_message_type : string &log &optional;
        header_length                   : count &log &optional;
    };

}
