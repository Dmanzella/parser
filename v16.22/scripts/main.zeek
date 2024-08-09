## main.zeek
##
## ICSNPP-BACNET
##
## Zeek script type/record definitions describing the information
## that will be written to the log files.
##

module BACNET;

export {
    redef enum Log::ID += {
                            LOG_GENERAL_LOG,
                            LOG_INITIALIZE_ROUTING_TABLE_PORTS_LOG,
                            LOG_PROPERTY_VALUE_LOG
                           };

    global log_general_log: event(rec: general_log);
    global log_initialize_routing_table_ports_log: event(rec: initialize_routing_table_ports_log);
    global log_property_value_log: event(rec: property_value_log);
    global emit_bacnet_general_log: function(c: connection);
    global emit_bacnet_initialize_routing_table_ports_log: function(c: connection);
    global emit_bacnet_property_value_log: function(c: connection);

}

# redefine connection record to contain one of each of the bacnet records
redef record connection += {
    bacnet_proto: string &optional;
    bacnet_general_log: general_log &optional;
    bacnet_initialize_routing_table_ports_log: initialize_routing_table_ports_log &optional;
    bacnet_property_value_log: property_value_log &optional;
};

#Put protocol detection information here
event zeek_init() &priority=5 {
    # initialize logging streams for all bacnet logs
    Log::create_stream(BACNET::LOG_GENERAL_LOG,
    [$columns=general_log,
    $ev=log_general_log,
    $path="bacnet_general"]);
    Log::create_stream(BACNET::LOG_INITIALIZE_ROUTING_TABLE_PORTS_LOG,
    [$columns=initialize_routing_table_ports_log,
    $ev=log_initialize_routing_table_ports_log,
    $path="bacnet_initialize_routing_table_ports"]);
    Log::create_stream(BACNET::LOG_PROPERTY_VALUE_LOG,
    [$columns=property_value_log,
    $ev=log_property_value_log,
    $path="bacnet_property_value"]);
}

function emit_bacnet_general_log(c: connection) {
    if (! c?$bacnet_general_log )
        return;
    if ( c?$bacnet_proto )
        c$bacnet_general_log$proto = c$bacnet_proto;
    Log::write(BACNET::LOG_GENERAL_LOG, c$bacnet_general_log);
    delete c$bacnet_general_log;
}

function emit_bacnet_initialize_routing_table_ports_log(c: connection) {
    if (! c?$bacnet_initialize_routing_table_ports_log )
        return;
    if ( c?$bacnet_proto )
        c$bacnet_initialize_routing_table_ports_log$proto = c$bacnet_proto;
    Log::write(BACNET::LOG_INITIALIZE_ROUTING_TABLE_PORTS_LOG, c$bacnet_initialize_routing_table_ports_log);
    delete c$bacnet_initialize_routing_table_ports_log;
}

function emit_bacnet_property_value_log(c: connection) {
    if (! c?$bacnet_property_value_log )
        return;
    if ( c?$bacnet_proto )
        c$bacnet_property_value_log$proto = c$bacnet_proto;
    Log::write(BACNET::LOG_PROPERTY_VALUE_LOG, c$bacnet_property_value_log);
    delete c$bacnet_property_value_log;
}


