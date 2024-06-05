## main.zeek
##
## ICSNPP-MYSIMPLEPROTOCOL
##
## Zeek script type/record definitions describing the information
## that will be written to the log files.
##

module MYSIMPLEPROTOCOL;

export {
    redef enum Log::ID += { LOG_GENERAL_LOG };

    global log_general_log: event(rec: general_log);
    global emit_mysimpleprotocol_general_log: function(c: connection);

}

# redefine connection record to contain one of each of the mysimpleprotocol records
redef record connection += {
    mysimpleprotocol_proto: string &optional;
    mysimpleprotocol_general_log: general_log &optional;
};

#Put protocol detection information here
event zeek_init() &priority=5 {
    # initialize logging streams for all mysimpleprotocol logs
                      Log::create_stream(MySimpleProtocol::LOG_GENERAL_LOG,
                      [$columns=general_log,
                      $ev=log_general_log,
                      $path="mysimpleprotocol_general_log"]);
}

function emit_mysimpleprotocol_general_log(c: connection) {
    if (! c?$mysimpleprotocol_general_log )
        return;
    if ( c?$mysimpleprotocol_proto )
        c$mysimpleprotocol_general_log$proto = c$mysimpleprotocol_proto;
    Log::write(MySimpleProtocol::LOG_GENERAL_LOG, c$mysimpleprotocol_general_log);
    delete c$mysimpleprotocol_general_log;
}


