# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

require 'rasn1'

module PacketGen::Plugin
  # GSS API
  #
  # A GSSAPI object is a ASN.1 SEQUENCE containing 2 elements:
  # * an OBJECT ID named +oid+, which value should be +1.3.6.1.5.5.2+
  # * a {NegTokenInit} object named +token+.
  #
  # == Examples
  #   # Access to oid
  #   gssapi[:oid]        #=> RASN1::Types::ObjectId
  #   gssapi[:oid].value  #=> "1.3.6.1.5.5.2"
  #   # Access to token
  #   gssapi[:token]                #=> PacketGen::Plugin::GSSAPI::NegTokenInit
  #   gssapi[:token][:mech_types]   #=> RASN1::Types::SequenceOf
  #   # Get mech_types as an array of OID strings
  #   gssapi[:token][:mech_types].value.map(&:value)
  #   # Get mech_token value
  #   gssapi[:token][:mech_token].value
  # @author Sylvain Daubert
  class GSSAPI < RASN1::Model
    # GSS API Negotiation Token Init
    #
    # A GSSAPI Negotiation Token Init is a ASN.1 SEQUENCE, explicitly tagged 0,
    # containing from 1 up to 4 elements:
    # * +mech_types+ is a mandatory SEQUENCE OF OBJECT ID. This SEQUENCE OF
    #   is explicitly tagged 0.
    # * +req_flags+ is an optional BIT STRING, explicitly tagged 1.
    # * +mech_token+ is an optional OCTET STRING, explicitly tagged 2.
    # * +mech_list_mic+ is an optional OCTET STRING, explicitly tagged 3.
    class NegTokenInit < RASN1::Model
      sequence :token, explicit: 0, class: :context, constructed: true,
               content: [sequence_of(:mech_types, RASN1::Types::ObjectId, explicit: 0, class: :context),
                         bit_string(:req_flags, explicit: 1, class: :context, constructed: true, optional: true),
                         octet_string(:mech_token, explicit: 2, class: :context, constructed: true, optional: true),
                         octet_string(:mech_list_mic, explicit: 3, class: :context, constructed: true, optional: true)]
    end

    sequence :gssapi, implicit: 0, class: :application,
             content: [objectid(:oid, value: '1.3.6.1.5.5.2'),
                       model(:token, NegTokenInit)]

    # Populate Object from +str+
    # @param [String] str
    # @return [self]
    def read(str)
      parse!(str, ber: true)
      self
    end

    # Get size of GSSAPI DER string, in bytes
    # @return [Integer]
    def sz
      to_der.size
    end
  end
end
