module MYSIMPLEPROTOCOL;

hook set_session_general_log(c: connection) {
    if ( ! c?$mysimpleprotocol_general_log )
        c$mysimpleprotocol_general_log = general_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto="mysimpleprotocol");
}

event MYSIMPLEPROTOCOL::MessageEvt (c: connection, is_orig: bool, message: MYSIMPLEPROTOCOL::Message) {
    hook set_session_general_log(c);

    local info_general_log = c$mysimpleprotocol_general_log;

    info_general_log$header_header_bits_version = message$header$headerBits$version;
    info_general_log$header_header_bits_message_type = MYSIMPLEPROTOCOL_ENUM::MESSAGE_TYPE[message$header$headerBits$messageType];
    info_general_log$header_length = message$header$length;
    info_general_log$body_data = message$body$data;
    MySimpleProtocol::emit_mysimpleprotocol_general_log(c);
}


