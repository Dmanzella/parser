module MYSIMPLEPROTOCOL_ENUM;

export {
    const MESSAGE_TYPE = {
        [MYSIMPLEPROTOCOL_ENUM::MessageType_ServerMessage]  = "Server Message",
        [MYSIMPLEPROTOCOL_ENUM::MessageType_ClientMessage]  = "Client Message"
    } &default=function(i: MYSIMPLEPROTOCOL_ENUM::MessageType):string{return fmt("unknown-0x%x", i); } &redef;

}
