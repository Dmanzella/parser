spicy_add_analyzer(
    NAME MySimpleProtocol
    PACKAGE_NAME MySimpleProtocol
    SOURCES zeek_mysimpleprotocol.spicy mysimpleprotocol_conversion.spicy mysimpleprotocol_conversion.cc mysimpleprotocol_generateid.spicy mysimpleprotocol_generateid.cc mysimpleprotocol.spicy mysimpleprotocol.evt mysimpleprotocol_enum.spicy
    SCRIPTS __load__.zeek main.zeek mysimpleprotocol_types.zeek mysimpleprotocol_processing.zeek mysimpleprotocol_enum.zeek
)
