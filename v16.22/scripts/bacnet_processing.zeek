module BACNET;

hook set_session_general_log(c: connection) {
    if ( ! c?$bacnet_general_log )
        c$bacnet_general_log = general_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto="bacnet");
}

hook set_session_initialize_routing_table_ports_log(c: connection) {
    if ( ! c?$bacnet_initialize_routing_table_ports_log )
        c$bacnet_initialize_routing_table_ports_log = initialize_routing_table_ports_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto="bacnet");
}

hook set_session_property_value_log(c: connection) {
    if ( ! c?$bacnet_property_value_log )
        c$bacnet_property_value_log = property_value_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto="bacnet");
}

event BACNET::MessageEvt (c: connection, is_orig: bool, message: BACNET::Message) {
    hook set_session_general_log(c);

    local info_general_log = c$bacnet_general_log;

    info_general_log$header_blvc_type = BACNET_ENUM::BLVC_TYPE[message$header$blvcType];
    info_general_log$header_blvc_function = BACNET_ENUM::BLVC_FUNCTION[message$header$blvcFunction];
    info_general_log$header_length = message$header$length;
    if (message$header?$forwardNPDU){
        info_general_log$forwarded_npdu_ip = message$header$forwardNPDU$ip;
        info_general_log$forwarded_npdu_port_number = message$header$forwardNPDU$portNumber;
    }
    info_general_log$body_version_number = message$body$versionNumber;
    info_general_log$body_npdu_control_apdu_or_npdu = message$body$npduControl$apduOrNPDU;
    info_general_log$body_npdu_control_destination_specifier = message$body$npduControl$destinationSpecifier;
    info_general_log$body_npdu_control_source_specifier = message$body$npduControl$sourceSpecifier;
    info_general_log$body_npdu_control_expecting_reply = message$body$npduControl$expectingReply;
    info_general_log$body_npdu_control_network_priority = BACNET_ENUM::NPDU_CONTROL_NET_PRIO[message$body$npduControl$networkPriority];
    if (message$body?$dnet){
        info_general_log$body_dnet = message$body$dnet;
    }
    if (message$body?$dlen){
        info_general_log$body_dlen = message$body$dlen;
    }
    if (message$body?$dadr){
        info_general_log$body_dadr = message$body$dadr;
    }
    if (message$body?$snet){
        info_general_log$body_snet = message$body$snet;
    }
    if (message$body?$slen){
        info_general_log$body_slen = message$body$slen;
    }
    if (message$body?$sadr){
        info_general_log$body_sadr = message$body$sadr;
    }
    if (message$body?$hopCount){
        info_general_log$body_hop_count = message$body$hopCount;
    }
    if (message$body?$npduMessageObject){
        info_general_log$npdu_message_object_npdu_message_type = BACNET_ENUM::NPDU_MESSAGE_TYPES[message$body$npduMessageObject$npduMessageType];
        if (message$body$npduMessageObject?$wirtnMessage){
            info_general_log$destination_addresses_destination_network_addresses = message$body$npduMessageObject$wirtnMessage$destinationNetworkAddresses;
        }
        if (message$body$npduMessageObject?$iartnMessage){
            info_general_log$destination_addresses_destination_network_addresses = message$body$npduMessageObject$iartnMessage$destinationNetworkAddresses;
        }
        if (message$body$npduMessageObject?$icbrtnMessage){
            info_general_log$i_could_be_router_to_network_destination_address = message$body$npduMessageObject$icbrtnMessage$destinationAddress;
            info_general_log$i_could_be_router_to_network_performance_index = message$body$npduMessageObject$icbrtnMessage$performanceIndex;
        }
        if (message$body$npduMessageObject?$rmtnMessage){
            info_general_log$reject_message_to_network_rejection_reason = BACNET_ENUM::REJECT_REASONS[message$body$npduMessageObject$rmtnMessage$rejectionReason];
            info_general_log$reject_message_to_network_rjmtn_destination_address = message$body$npduMessageObject$rmtnMessage$rjmtnDestinationAddress;
        }
        if (message$body$npduMessageObject?$rbtnMessage){
            info_general_log$destination_addresses_destination_network_addresses = message$body$npduMessageObject$rbtnMessage$destinationNetworkAddresses;
        }
        if (message$body$npduMessageObject?$ratnMessage){
            info_general_log$destination_addresses_destination_network_addresses = message$body$npduMessageObject$ratnMessage$destinationNetworkAddresses;
        }
        if (message$body$npduMessageObject?$irtMessage){
            info_general_log$initialize_routing_table_ports_link_id = message$body$npduMessageObject$irtMessage$initializeRoutingTablePortsLinkID;
            info_general_log$initialize_routing_table_number_of_ports = message$body$npduMessageObject$irtMessage$numberOfPorts;
        }
        if (message$body$npduMessageObject?$irtaMessage){
            info_general_log$initialize_routing_table_ports_link_id = message$body$npduMessageObject$irtaMessage$initializeRoutingTablePortsLinkID;
            info_general_log$initialize_routing_table_number_of_ports = message$body$npduMessageObject$irtaMessage$numberOfPorts;
        }
        if (message$body$npduMessageObject?$ectnMessage){
            info_general_log$establish_connection_to_network_ectn_dnet = message$body$npduMessageObject$ectnMessage$ectnDNET;
            info_general_log$establish_connection_to_network_termination_time_value = message$body$npduMessageObject$ectnMessage$TerminationTimeValue;
        }
        if (message$body$npduMessageObject?$dctnMessage){
            info_general_log$disconnect_connection_to_network_dctn_dnet = message$body$npduMessageObject$dctnMessage$dctnDNET;
        }
        if (message$body$npduMessageObject?$niMessage){
            info_general_log$network_number_is_nni_dnet = message$body$npduMessageObject$niMessage$nniDNET;
            info_general_log$network_number_is_network_number_is_enum = BACNET_ENUM::NETWORK_NUMBER_IS_ENUM[message$body$npduMessageObject$niMessage$networkNumberIsEnum];
        }
        if (message$body$npduMessageObject?$data){
            info_general_log$npdu_message_object_data = message$body$npduMessageObject$data;
        }
    }
    if (message$body?$apduMessageObject){
        info_general_log$apdu_message_object_apdu_type_pdu_type = BACNET_ENUM::APDU_TYPES[message$body$apduMessageObject$apduType$pduType];
        info_general_log$apdu_message_object_apdu_type_seg = message$body$apduMessageObject$apduType$seg;
        info_general_log$apdu_message_object_apdu_type_mor = message$body$apduMessageObject$apduType$mor;
        info_general_log$apdu_message_object_apdu_type_sa = message$body$apduMessageObject$apduType$sa;
        info_general_log$apdu_message_object_apdu_type_srv = message$body$apduMessageObject$apduType$srv;
        if (message$body$apduMessageObject?$confirmedReq){
            info_general_log$confirmed_request_confirmed_request_bits_max_segs = message$body$apduMessageObject$confirmedReq$confirmedRequestBits$maxSegs;
            info_general_log$confirmed_request_confirmed_request_bits_max_resp = message$body$apduMessageObject$confirmedReq$confirmedRequestBits$maxResp;
            info_general_log$confirmed_request_confirmed_invoke_id = message$body$apduMessageObject$confirmedReq$confirmedInvokeID;
            if (message$body$apduMessageObject$confirmedReq?$sequenceNumber){
                info_general_log$confirmed_request_sequence_number = message$body$apduMessageObject$confirmedReq$sequenceNumber;
            }
            if (message$body$apduMessageObject$confirmedReq?$proposedSizeWindow){
                info_general_log$confirmed_request_proposed_size_window = message$body$apduMessageObject$confirmedReq$proposedSizeWindow;
            }
            info_general_log$confirmed_request_confirmed_service_choice = BACNET_ENUM::CONFIRMED_SERVICE_CHOICES[message$body$apduMessageObject$confirmedReq$confirmedServiceChoice];
            if (message$body$apduMessageObject$confirmedReq?$readProperty){
                info_general_log$object_identifier_device_identifier_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$confirmedReq$readProperty$objectIdentifier$deviceIdentifier$tagNumber];
                info_general_log$object_identifier_device_identifier_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$confirmedReq$readProperty$objectIdentifier$deviceIdentifier$class];
                info_general_log$object_identifier_device_identifier_length_value_type = message$body$apduMessageObject$confirmedReq$readProperty$objectIdentifier$deviceIdentifier$lengthValueType;
                info_general_log$object_identifier_object_identifier_bits_object_type = BACNET_ENUM::OBJECT_TYPES[message$body$apduMessageObject$confirmedReq$readProperty$objectIdentifier$objectIdentifierBits$ObjectType];
                info_general_log$object_identifier_object_identifier_bits_instance_number = message$body$apduMessageObject$confirmedReq$readProperty$objectIdentifier$objectIdentifierBits$InstanceNumber;
                info_general_log$read_property_property_tags_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$confirmedReq$readProperty$propertyTags$tagNumber];
                info_general_log$read_property_property_tags_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$confirmedReq$readProperty$propertyTags$class];
                info_general_log$read_property_property_tags_length_value_type = message$body$apduMessageObject$confirmedReq$readProperty$propertyTags$lengthValueType;
                if (message$body$apduMessageObject$confirmedReq$readProperty?$propertyIdentifier){
                    info_general_log$read_property_property_identifier = BACNET_ENUM::PROPERTY_IDENTIFIER_ENUM[message$body$apduMessageObject$confirmedReq$readProperty$propertyIdentifier];
                }
                if (message$body$apduMessageObject$confirmedReq$readProperty?$propertyIdentifier2){
                    info_general_log$read_property_property_identifier2 = BACNET_ENUM::PROPERTY_IDENTIFIER_ENUM2[message$body$apduMessageObject$confirmedReq$readProperty$propertyIdentifier2];
                }
                info_general_log$read_property_property_array_index_data = message$body$apduMessageObject$confirmedReq$readProperty$propertyArrayIndexData;
            }
            if (message$body$apduMessageObject$confirmedReq?$writeProperty){
                info_general_log$object_identifier_device_identifier_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$confirmedReq$writeProperty$objectIdentifier$deviceIdentifier$tagNumber];
                info_general_log$object_identifier_device_identifier_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$confirmedReq$writeProperty$objectIdentifier$deviceIdentifier$class];
                info_general_log$object_identifier_device_identifier_length_value_type = message$body$apduMessageObject$confirmedReq$writeProperty$objectIdentifier$deviceIdentifier$lengthValueType;
                info_general_log$object_identifier_object_identifier_bits_object_type = BACNET_ENUM::OBJECT_TYPES[message$body$apduMessageObject$confirmedReq$writeProperty$objectIdentifier$objectIdentifierBits$ObjectType];
                info_general_log$object_identifier_object_identifier_bits_instance_number = message$body$apduMessageObject$confirmedReq$writeProperty$objectIdentifier$objectIdentifierBits$InstanceNumber;
                info_general_log$write_property_property_tags_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$confirmedReq$writeProperty$propertyTags$tagNumber];
                info_general_log$write_property_property_tags_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$confirmedReq$writeProperty$propertyTags$class];
                info_general_log$write_property_property_tags_length_value_type = message$body$apduMessageObject$confirmedReq$writeProperty$propertyTags$lengthValueType;
                if (message$body$apduMessageObject$confirmedReq$writeProperty?$propertyIdentifier){
                    info_general_log$write_property_property_identifier = BACNET_ENUM::PROPERTY_IDENTIFIER_ENUM[message$body$apduMessageObject$confirmedReq$writeProperty$propertyIdentifier];
                }
                if (message$body$apduMessageObject$confirmedReq$writeProperty?$propertyIdentifier2){
                    info_general_log$write_property_property_identifier2 = BACNET_ENUM::PROPERTY_IDENTIFIER_ENUM2[message$body$apduMessageObject$confirmedReq$writeProperty$propertyIdentifier2];
                }
                info_general_log$write_property_opening_tag_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$confirmedReq$writeProperty$openingTag$tagNumber];
                info_general_log$write_property_opening_tag_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$confirmedReq$writeProperty$openingTag$class];
                info_general_log$write_property_opening_tag_length_value_type = message$body$apduMessageObject$confirmedReq$writeProperty$openingTag$lengthValueType;
                info_general_log$write_property_property_tag_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$confirmedReq$writeProperty$propertyTag$tagNumber];
                info_general_log$write_property_property_tag_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$confirmedReq$writeProperty$propertyTag$class];
                info_general_log$write_property_property_tag_length_value_type = message$body$apduMessageObject$confirmedReq$writeProperty$propertyTag$lengthValueType;
                if (message$body$apduMessageObject$confirmedReq$writeProperty?$propertyData){
                    info_general_log$write_property_property_data = message$body$apduMessageObject$confirmedReq$writeProperty$propertyData;
                }
                if (message$body$apduMessageObject$confirmedReq$writeProperty?$propertyData2){
                    info_general_log$write_property_property_data2 = message$body$apduMessageObject$confirmedReq$writeProperty$propertyData2;
                }
                if (message$body$apduMessageObject$confirmedReq$writeProperty?$propertyData3){
                    info_general_log$int24_bit_int_val = message$body$apduMessageObject$confirmedReq$writeProperty$propertyData3$intVal;
                }
                if (message$body$apduMessageObject$confirmedReq$writeProperty?$realData){
                    info_general_log$write_property_real_data = message$body$apduMessageObject$confirmedReq$writeProperty$realData;
                }
                info_general_log$write_property_rest_of_data = message$body$apduMessageObject$confirmedReq$writeProperty$restOfData;
            }
        }
        if (message$body$apduMessageObject?$unconfirmedREQ){
            info_general_log$unconfirmed_request_unconfirmed_service_choice = BACNET_ENUM::UNCONFIRMED_SERVICE_CHOICES[message$body$apduMessageObject$unconfirmedREQ$unconfirmedServiceChoice];
            if (message$body$apduMessageObject$unconfirmedREQ?$iAm){
                info_general_log$object_identifier_device_identifier_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$unconfirmedREQ$iAm$iAmDeviceIdentifier$deviceIdentifier$tagNumber];
                info_general_log$object_identifier_device_identifier_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$unconfirmedREQ$iAm$iAmDeviceIdentifier$deviceIdentifier$class];
                info_general_log$object_identifier_device_identifier_length_value_type = message$body$apduMessageObject$unconfirmedREQ$iAm$iAmDeviceIdentifier$deviceIdentifier$lengthValueType;
                info_general_log$object_identifier_object_identifier_bits_object_type = BACNET_ENUM::OBJECT_TYPES[message$body$apduMessageObject$unconfirmedREQ$iAm$iAmDeviceIdentifier$objectIdentifierBits$ObjectType];
                info_general_log$object_identifier_object_identifier_bits_instance_number = message$body$apduMessageObject$unconfirmedREQ$iAm$iAmDeviceIdentifier$objectIdentifierBits$InstanceNumber;
                info_general_log$i_am_i_am_max_length_tag_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$unconfirmedREQ$iAm$iAmMaxLengthTag$tagNumber];
                info_general_log$i_am_i_am_max_length_tag_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$unconfirmedREQ$iAm$iAmMaxLengthTag$class];
                info_general_log$i_am_i_am_max_length_tag_length_value_type = message$body$apduMessageObject$unconfirmedREQ$iAm$iAmMaxLengthTag$lengthValueType;
                if (message$body$apduMessageObject$unconfirmedREQ$iAm?$maximumApduLength){
                    info_general_log$i_am_maximum_apdu_length = message$body$apduMessageObject$unconfirmedREQ$iAm$maximumApduLength;
                }
                if (message$body$apduMessageObject$unconfirmedREQ$iAm?$maxmiumApduLength2){
                    info_general_log$i_am_maxmium_apdu_length2 = message$body$apduMessageObject$unconfirmedREQ$iAm$maxmiumApduLength2;
                }
                info_general_log$i_am_segmentation_supported_tag_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$unconfirmedREQ$iAm$segmentationSupportedTag$tagNumber];
                info_general_log$i_am_segmentation_supported_tag_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$unconfirmedREQ$iAm$segmentationSupportedTag$class];
                info_general_log$i_am_segmentation_supported_tag_length_value_type = message$body$apduMessageObject$unconfirmedREQ$iAm$segmentationSupportedTag$lengthValueType;
                info_general_log$i_am_segmentation_supported = BACNET_ENUM::SEGMENTATION_ENUM[message$body$apduMessageObject$unconfirmedREQ$iAm$segmentationSupported];
                info_general_log$i_am_vendor_id_tag_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$unconfirmedREQ$iAm$VendorIDTag$tagNumber];
                info_general_log$i_am_vendor_id_tag_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$unconfirmedREQ$iAm$VendorIDTag$class];
                info_general_log$i_am_vendor_id_tag_length_value_type = message$body$apduMessageObject$unconfirmedREQ$iAm$VendorIDTag$lengthValueType;
                if (message$body$apduMessageObject$unconfirmedREQ$iAm?$vendorID){
                    info_general_log$i_am_vendor_id = BACNET_ENUM::VENDOR_ID1[message$body$apduMessageObject$unconfirmedREQ$iAm$vendorID];
                }
                if (message$body$apduMessageObject$unconfirmedREQ$iAm?$vendorID2){
                    info_general_log$i_am_vendor_id2 = BACNET_ENUM::VENDOR_ID2[message$body$apduMessageObject$unconfirmedREQ$iAm$vendorID2];
                }
            }
            if (message$body$apduMessageObject$unconfirmedREQ?$iHave){
                info_general_log$object_identifier_device_identifier_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$unconfirmedREQ$iHave$objectIdentifier1$deviceIdentifier$tagNumber];
                info_general_log$object_identifier_device_identifier_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$unconfirmedREQ$iHave$objectIdentifier1$deviceIdentifier$class];
                info_general_log$object_identifier_device_identifier_length_value_type = message$body$apduMessageObject$unconfirmedREQ$iHave$objectIdentifier1$deviceIdentifier$lengthValueType;
                info_general_log$object_identifier_object_identifier_bits_object_type = BACNET_ENUM::OBJECT_TYPES[message$body$apduMessageObject$unconfirmedREQ$iHave$objectIdentifier1$objectIdentifierBits$ObjectType];
                info_general_log$object_identifier_object_identifier_bits_instance_number = message$body$apduMessageObject$unconfirmedREQ$iHave$objectIdentifier1$objectIdentifierBits$InstanceNumber;
                info_general_log$object_identifier_device_identifier_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$unconfirmedREQ$iHave$objectIdentifier2$deviceIdentifier$tagNumber];
                info_general_log$object_identifier_device_identifier_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$unconfirmedREQ$iHave$objectIdentifier2$deviceIdentifier$class];
                info_general_log$object_identifier_device_identifier_length_value_type = message$body$apduMessageObject$unconfirmedREQ$iHave$objectIdentifier2$deviceIdentifier$lengthValueType;
                info_general_log$object_identifier_object_identifier_bits_object_type = BACNET_ENUM::OBJECT_TYPES[message$body$apduMessageObject$unconfirmedREQ$iHave$objectIdentifier2$objectIdentifierBits$ObjectType];
                info_general_log$object_identifier_object_identifier_bits_instance_number = message$body$apduMessageObject$unconfirmedREQ$iHave$objectIdentifier2$objectIdentifierBits$InstanceNumber;
                info_general_log$object_name_object_name_tags_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$unconfirmedREQ$iHave$objectName$objectNameTags$tagNumber];
                info_general_log$object_name_object_name_tags_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$unconfirmedREQ$iHave$objectName$objectNameTags$class];
                info_general_log$object_name_object_name_tags_length_value_type = message$body$apduMessageObject$unconfirmedREQ$iHave$objectName$objectNameTags$lengthValueType;
                info_general_log$object_name_extended_length = message$body$apduMessageObject$unconfirmedREQ$iHave$objectName$extendedLength;
                info_general_log$object_name_character_string_set = BACNET_ENUM::CHARACTER_STRING_ENUM[message$body$apduMessageObject$unconfirmedREQ$iHave$objectName$characterStringSet];
                info_general_log$object_name_object_name = message$body$apduMessageObject$unconfirmedREQ$iHave$objectName$objectName;
            }
            if (message$body$apduMessageObject$unconfirmedREQ?$unconfirmedCovNotification){
                info_general_log$unconfirmed_cov_notification_data10 = message$body$apduMessageObject$unconfirmedREQ$unconfirmedCovNotification$data10;
            }
            if (message$body$apduMessageObject$unconfirmedREQ?$unconfirmedEventNotification){
                info_general_log$unconfirmed_event_notification_data11 = message$body$apduMessageObject$unconfirmedREQ$unconfirmedEventNotification$data11;
            }
            if (message$body$apduMessageObject$unconfirmedREQ?$unconfirmedPrivateTransfer){
                info_general_log$unconfirmed_private_transfer_data12 = message$body$apduMessageObject$unconfirmedREQ$unconfirmedPrivateTransfer$data12;
            }
            if (message$body$apduMessageObject$unconfirmedREQ?$unconfirmedTextMessage){
                info_general_log$unconfirmed_text_message_data13 = message$body$apduMessageObject$unconfirmedREQ$unconfirmedTextMessage$data13;
            }
            if (message$body$apduMessageObject$unconfirmedREQ?$timeSynchronization){
                info_general_log$time_synchronization_data14 = message$body$apduMessageObject$unconfirmedREQ$timeSynchronization$data14;
            }
            if (message$body$apduMessageObject$unconfirmedREQ?$whoHas){
                info_general_log$who_has_who_has_data = message$body$apduMessageObject$unconfirmedREQ$whoHas$WhoHasData;
            }
            if (message$body$apduMessageObject$unconfirmedREQ?$whoIs){
                if (message$body$apduMessageObject$unconfirmedREQ$whoIs?$deviceLowLimitTags){
                    info_general_log$who_is_device_low_limit_tags_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$unconfirmedREQ$whoIs$deviceLowLimitTags$tagNumber];
                    info_general_log$who_is_device_low_limit_tags_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$unconfirmedREQ$whoIs$deviceLowLimitTags$class];
                    info_general_log$who_is_device_low_limit_tags_length_value_type = message$body$apduMessageObject$unconfirmedREQ$whoIs$deviceLowLimitTags$lengthValueType;
                }
                if (message$body$apduMessageObject$unconfirmedREQ$whoIs?$deviceLowLimit){
                    info_general_log$who_is_device_low_limit = message$body$apduMessageObject$unconfirmedREQ$whoIs$deviceLowLimit;
                }
                if (message$body$apduMessageObject$unconfirmedREQ$whoIs?$deviceLowLimit2){
                    info_general_log$who_is_device_low_limit2 = message$body$apduMessageObject$unconfirmedREQ$whoIs$deviceLowLimit2;
                }
                if (message$body$apduMessageObject$unconfirmedREQ$whoIs?$deviceLowLimit3){
                    info_general_log$device_limit_low_device_limit_low = message$body$apduMessageObject$unconfirmedREQ$whoIs$deviceLowLimit3$deviceLimitLow;
                }
                if (message$body$apduMessageObject$unconfirmedREQ$whoIs?$deviceHighLimitTags){
                    info_general_log$who_is_device_high_limit_tags_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$unconfirmedREQ$whoIs$deviceHighLimitTags$tagNumber];
                    info_general_log$who_is_device_high_limit_tags_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$unconfirmedREQ$whoIs$deviceHighLimitTags$class];
                    info_general_log$who_is_device_high_limit_tags_length_value_type = message$body$apduMessageObject$unconfirmedREQ$whoIs$deviceHighLimitTags$lengthValueType;
                }
                if (message$body$apduMessageObject$unconfirmedREQ$whoIs?$deviceHighLimit){
                    info_general_log$who_is_device_high_limit = message$body$apduMessageObject$unconfirmedREQ$whoIs$deviceHighLimit;
                }
                if (message$body$apduMessageObject$unconfirmedREQ$whoIs?$deviceHighLimit2){
                    info_general_log$who_is_device_high_limit2 = message$body$apduMessageObject$unconfirmedREQ$whoIs$deviceHighLimit2;
                }
                if (message$body$apduMessageObject$unconfirmedREQ$whoIs?$deviceHighLimit3){
                    info_general_log$device_limit_high_device_limit_high = message$body$apduMessageObject$unconfirmedREQ$whoIs$deviceHighLimit3$deviceLimitHigh;
                }
            }
            if (message$body$apduMessageObject$unconfirmedREQ?$utcTimeSynchronization){
                info_general_log$utc_time_synchronization_data17 = message$body$apduMessageObject$unconfirmedREQ$utcTimeSynchronization$data17;
            }
        }
        if (message$body$apduMessageObject?$simpleAck){
            info_general_log$simple_ack_simple_invoke_id = message$body$apduMessageObject$simpleAck$simpleInvokeID;
            info_general_log$simple_ack_confirmed_service_choice = BACNET_ENUM::CONFIRMED_SERVICE_CHOICES[message$body$apduMessageObject$simpleAck$confirmedServiceChoice];
        }
        if (message$body$apduMessageObject?$complexAck){
            info_general_log$complex_ack_original_invoke_id = message$body$apduMessageObject$complexAck$OriginalInvokeID;
            if (message$body$apduMessageObject$complexAck?$sequenceNumber){
                info_general_log$complex_ack_sequence_number = message$body$apduMessageObject$complexAck$sequenceNumber;
            }
            if (message$body$apduMessageObject$complexAck?$proposedWindowsSize){
                info_general_log$complex_ack_proposed_windows_size = message$body$apduMessageObject$complexAck$proposedWindowsSize;
            }
            info_general_log$complex_ack_service_ack_choice = BACNET_ENUM::CONFIRMED_SERVICE_CHOICES[message$body$apduMessageObject$complexAck$serviceAckChoice];
            if (message$body$apduMessageObject$complexAck?$readPropertyAck){
                info_general_log$property_value_link_id = message$body$apduMessageObject$complexAck$readPropertyAck$propertyValueLinkID;
                info_general_log$object_identifier_device_identifier_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$complexAck$readPropertyAck$objectIdentifier$deviceIdentifier$tagNumber];
                info_general_log$object_identifier_device_identifier_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$complexAck$readPropertyAck$objectIdentifier$deviceIdentifier$class];
                info_general_log$object_identifier_device_identifier_length_value_type = message$body$apduMessageObject$complexAck$readPropertyAck$objectIdentifier$deviceIdentifier$lengthValueType;
                info_general_log$object_identifier_object_identifier_bits_object_type = BACNET_ENUM::OBJECT_TYPES[message$body$apduMessageObject$complexAck$readPropertyAck$objectIdentifier$objectIdentifierBits$ObjectType];
                info_general_log$object_identifier_object_identifier_bits_instance_number = message$body$apduMessageObject$complexAck$readPropertyAck$objectIdentifier$objectIdentifierBits$InstanceNumber;
                info_general_log$property_identifier_property_tags_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$complexAck$readPropertyAck$propertyIdentifier$propertyTags$tagNumber];
                info_general_log$property_identifier_property_tags_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$complexAck$readPropertyAck$propertyIdentifier$propertyTags$class];
                info_general_log$property_identifier_property_tags_length_value_type = message$body$apduMessageObject$complexAck$readPropertyAck$propertyIdentifier$propertyTags$lengthValueType;
                if (message$body$apduMessageObject$complexAck$readPropertyAck$propertyIdentifier?$propertyIdentifier){
                    info_general_log$property_identifier_property_identifier = BACNET_ENUM::PROPERTY_IDENTIFIER_ENUM[message$body$apduMessageObject$complexAck$readPropertyAck$propertyIdentifier$propertyIdentifier];
                }
                info_general_log$read_property_ack_opening_tag_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$complexAck$readPropertyAck$openingTag$tagNumber];
                info_general_log$read_property_ack_opening_tag_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$complexAck$readPropertyAck$openingTag$class];
                info_general_log$read_property_ack_opening_tag_length_value_type = message$body$apduMessageObject$complexAck$readPropertyAck$openingTag$lengthValueType;
                if (message$body$apduMessageObject$complexAck$readPropertyAck?$propertyList){
                }
                info_general_log$read_property_ack_closing_tag_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$complexAck$readPropertyAck$closingTag$tagNumber];
                info_general_log$read_property_ack_closing_tag_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$complexAck$readPropertyAck$closingTag$class];
                info_general_log$read_property_ack_closing_tag_length_value_type = message$body$apduMessageObject$complexAck$readPropertyAck$closingTag$lengthValueType;
                info_general_log$read_property_ack_rest_of_data = message$body$apduMessageObject$complexAck$readPropertyAck$restOfData;
            }
        }
        if (message$body$apduMessageObject?$segmentAck){
            info_general_log$segment_ack_original_invoke_id = message$body$apduMessageObject$segmentAck$OriginalInvokeID;
            info_general_log$segment_ack_sequence_number = message$body$apduMessageObject$segmentAck$sequenceNumber;
            info_general_log$segment_ack_actual_window_size = message$body$apduMessageObject$segmentAck$actualWindowSize;
        }
        if (message$body$apduMessageObject?$errorPdu){
            info_general_log$error_pdu_original_invoke_id = message$body$apduMessageObject$errorPdu$OriginalInvokeID;
            info_general_log$error_pdu_confirmed_service_choice = BACNET_ENUM::CONFIRMED_SERVICE_CHOICES[message$body$apduMessageObject$errorPdu$confirmedServiceChoice];
            info_general_log$error_pdu_error_class_tags_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$errorPdu$errorClassTags$tagNumber];
            info_general_log$error_pdu_error_class_tags_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$errorPdu$errorClassTags$class];
            info_general_log$error_pdu_error_class_tags_length_value_type = message$body$apduMessageObject$errorPdu$errorClassTags$lengthValueType;
            info_general_log$error_pdu_error_class = BACNET_ENUM::ERROR_CLASS[message$body$apduMessageObject$errorPdu$errorClass];
            info_general_log$error_pdu_error_code_tags_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[message$body$apduMessageObject$errorPdu$errorCodeTags$tagNumber];
            info_general_log$error_pdu_error_code_tags_class = BACNET_ENUM::TAG_TYPE[message$body$apduMessageObject$errorPdu$errorCodeTags$class];
            info_general_log$error_pdu_error_code_tags_length_value_type = message$body$apduMessageObject$errorPdu$errorCodeTags$lengthValueType;
            info_general_log$error_pdu_error_code = BACNET_ENUM::ERROR_CODES[message$body$apduMessageObject$errorPdu$errorCode];
        }
        if (message$body$apduMessageObject?$rejectPdu){
            info_general_log$reject_pdu_original_invoke_id = message$body$apduMessageObject$rejectPdu$originalInvokeID;
            info_general_log$reject_pdu_reject_reason = BACNET_ENUM::APDU_REJECT_REASONS[message$body$apduMessageObject$rejectPdu$rejectReason];
        }
        if (message$body$apduMessageObject?$abortPdu){
            info_general_log$abort_pdu_original_invoke_id = message$body$apduMessageObject$abortPdu$originalInvokeID;
            info_general_log$abort_pdu_abort_reason = BACNET_ENUM::ABORT_REASONS[message$body$apduMessageObject$abortPdu$abortReason];
        }
        if (message$body$apduMessageObject?$data){
            info_general_log$apdu_message_object_data = message$body$apduMessageObject$data;
        }
    }
    BACNET::emit_bacnet_general_log(c);
}

event BACNET::initializeRoutingTablePortsEvt (c: connection, is_orig: bool, initializeroutingtableports: BACNET::initializeRoutingTablePorts) {
    hook set_session_initialize_routing_table_ports_log(c);

    local info_initialize_routing_table_ports_log = c$bacnet_initialize_routing_table_ports_log;

    info_initialize_routing_table_ports_log$initialize_routing_table_ports_link_id = initializeroutingtableports$initializeRoutingTablePortsLinkID;
    info_initialize_routing_table_ports_log$initialize_routing_table_ports_connected_dnet = initializeroutingtableports$connectedDNET;
    info_initialize_routing_table_ports_log$initialize_routing_table_ports_port_id = initializeroutingtableports$portID;
    info_initialize_routing_table_ports_log$initialize_routing_table_ports_port_info_length = initializeroutingtableports$portInfoLength;
    info_initialize_routing_table_ports_log$initialize_routing_table_ports_port_info = initializeroutingtableports$portInfo;
    BACNET::emit_bacnet_initialize_routing_table_ports_log(c);
}

event BACNET::propertyValueEvt (c: connection, is_orig: bool, propertyvalue: BACNET::propertyValue) {
    hook set_session_property_value_log(c);

    local info_property_value_log = c$bacnet_property_value_log;

    info_property_value_log$property_value_link_id = propertyvalue$propertyValueLinkID;
    info_property_value_log$property_value_property_tag_tag_number = BACNET_ENUM::OBJECT_IDENTIFIER[propertyvalue$propertyTag$tagNumber];
    info_property_value_log$property_value_property_tag_class = BACNET_ENUM::TAG_TYPE[propertyvalue$propertyTag$class];
    info_property_value_log$property_value_property_tag_length_value_type = propertyvalue$propertyTag$lengthValueType;
    if (propertyvalue?$propertyData){
        info_property_value_log$property_value_property_data = propertyvalue$propertyData;
    }
    if (propertyvalue?$propertyData2){
        info_property_value_log$property_value_property_data2 = propertyvalue$propertyData2;
    }
    if (propertyvalue?$threeByteData){
        info_property_value_log$int24_bit_int_val = propertyvalue$threeByteData$intVal;
    }
    if (propertyvalue?$propertyData4){
        info_property_value_log$property_value_property_data4 = propertyvalue$propertyData4;
    }
    BACNET::emit_bacnet_property_value_log(c);
}


