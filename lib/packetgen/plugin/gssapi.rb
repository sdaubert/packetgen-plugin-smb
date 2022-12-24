# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

require 'rasn1'

module PacketGen::Plugin
  # GSS API, from RFC 4178
  #
  #    GSSAPI ::= CHOICE {
  #       init        InitialContextToken,
  #       token_resp  NegTokenResp
  #    }
  #
  #    InitialContextToken ::= [APPLICATION 0] IMPLICIT SEQUENCE {
  #       oid         OBJECT IDENTIFIER,
  #       token_init  NegTokenInit
  #    }
  #
  #    NegTokenInit ::= [0] EXPLICIT SEQUENCE {
  #       mechTypes       [0] MechTypeList,
  #       reqFlags        [1] BIT STRING    OPTIONAL, -- No more used
  #       mechToken       [2] OCTET STRING  OPTIONAL,
  #       mechListMIC     [3] OCTET STRING  OPTIONAL,
  #    }
  #
  #    NegTokenResp ::= [1] EXPLICIT SEQUENCE {
  #       negState       [0] ENUMERATED {
  #         accept-completed    (0),
  #         accept-incomplete   (1),
  #         reject              (2),
  #         request-mic         (3)
  #       }                                 OPTIONAL,
  #       supportedMech   [1] MechType      OPTIONAL,
  #       responseToken   [2] OCTET STRING  OPTIONAL,
  #       mechListMIC     [3] OCTET STRING  OPTIONAL,
  #    }
  #
  # @example initial context
  #   gssapi.chosen   #=> 0
  #   # Access to oid of initial context
  #   gssapi[:oid]        #=> RASN1::Types::ObjectId
  #   gssapi[:oid].value  #=> "1.3.6.1.5.5.2"
  #   # Access to token_init
  #   gssapi[:token_init]                #=> PacketGen::Plugin::GSSAPI::NegTokenInit
  #   gssapi[:token_init][:mech_types]   #=> RASN1::Types::SequenceOf
  #   # Get mech_types as an array of OID strings
  #   gssapi[:token_init][:mech_types].value.map(&:value)
  #   # Get mech_token value
  #   gssapi[:token_init][:mech_token].value
  #
  # @example response token
  #   gssapi.chosen   #=> 1
  #   gssapi[:token_resp][:negstate]             #=> RASN1::Types::Enumerated
  #   gssapi[:token_resp][:negstate].value       #=> String
  #   gssapi[:token_resp][:supported_mech]       #=> RASN1::Types::ObjectId
  #   gssapi[:token_resp][:supported_mech].value #=> String
  #   gssapi[:token_resp][:response]             #=> RASN1::Types::OctetString
  # @author Sylvain Daubert
  class GSSAPI < RASN1::Model
    include PacketGen::Types::Fieldable

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
      sequence :token,
               explicit: 0, class: :context, constructed: true,
               content: [sequence_of(:mech_types, RASN1::Types::ObjectId, explicit: 0, class: :context),
                         bit_string(:req_flags, explicit: 1, class: :context, constructed: true, optional: true),
                         octet_string(:mech_token, explicit: 2, class: :context, constructed: true, optional: true),
                         any(:mech_list_mic, explicit: 3, class: :context, constructed: true, optional: true)]
    end

    # GSS API Negotiation Token Response
    class NegTokenResp < RASN1::Model
      # Negotiation states
      NEG_STATES = {
        'accept-completed' => 0,
        'accept-incomplete' => 1,
        'reject' => 2,
        'request-mic' => 3
      }.freeze
      sequence :token,
               explicit: 1, class: :context, constructed: true,
               content: [enumerated(:negstate, enum: NEG_STATES, explicit: 0, class: :context, constructed: true, optional: true),
                         objectid(:supported_mech, explicit: 1, class: :context, constructed: true, optional: true),
                         octet_string(:response, explicit: 2, class: :context, constructed: true, optional: true),
                         octet_string(:mech_list_mic, explicit: 3, class: :context, constructed: true, optional: true)]
    end

    class NegTokenInitEnvelop < RASN1::Model
      sequence(:init, implicit: 0, class: :application,
                      content: [objectid(:oid, value: '1.3.6.1.5.5.2'),
                                model(:token_init, NegTokenInit)])
    end

    choice :gssapi,
           content: [model(:init_env, NegTokenInitEnvelop),
                     model(:token_resp, NegTokenResp)]

    # @param [Hash] args
    # @option args [Symbol] :token +:init+ or +:response+ to force selection of
    #  token CHOICE.
    def initialize(args={})
      token = args.delete(:token)
      super
      self[:gssapi].chosen = token == :init ? 0 : 1
    end

    # Populate Object from +str+
    # @param [String] str
    # @return [self]
    def read(str)
      return self if str.nil?

      parse!(str, ber: true)
      self
    end

    def to_human
      inspect
    end

    alias to_s to_der
  end
end
