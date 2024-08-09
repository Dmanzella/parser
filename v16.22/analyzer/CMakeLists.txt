spicy_add_analyzer(
    NAME BACnet
    PACKAGE_NAME BACnet
    SOURCES zeek_bacnet.spicy bacnet_conversion.spicy bacnet_conversion.cc bacnet_generateid.spicy bacnet_generateid.cc bacnet.spicy bacnet.evt bacnet_enum.spicy
    SCRIPTS __load__.zeek main.zeek bacnet_types.zeek bacnet_processing.zeek bacnet_enum.zeek
)
