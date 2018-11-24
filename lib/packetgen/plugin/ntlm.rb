# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  # Base class for NTLM authentication protocol.
  # @author Sylvain Daubert
  class NTLM < PacketGen::Types::Fields
    # NTLM message types
    TYPES = {
      'negotiate' => 1,
      'challenge' => 2,
      'authenticate' => 3
    }.freeze

    # NTLM signature
    SIGNATURE = "NTLMSSP\0"

    # void version
    VOID_VERSION = [0].pack('q').freeze

    # @!attribute signature
    #  8-byte NTLM signature
    #  @return [String]
    define_field :signature, PacketGen::Types::String, static_length: 8, default: SIGNATURE
    # @!attribute type
    #  4-byte message type
    #  @return [Integer]
    define_field :type, PacketGen::Types::Int32leEnum, enum: TYPES
    # @!attribute payload
    #  @return [String]
    define_field :payload, PacketGen::Types::String

    # Create a NTLM object from a binary string
    # @param [String] str
    # @return [NTLM]
    def self.read(str)
      ntlm = self.new.read(str)
      type = TYPES.key(ntlm.type)
      return ntlm if type.nil?

      klass = NTLM.const_get(type.capitalize)
      klass.new.read(str)
    end

    # Define a flags field.
    def self.define_negotiate_flags
      define_field_before :payload, :flags, PacketGen::Types::Int32le
      define_bit_fields_on :flags, :flags_w, :flags_v, :flags_u, :flags_r13, 3,
                           :flags_t, :flags_r4, :flags_s, :flags_r,
                           :flags_r5, :flags_q, :flags_p, :flags_r6,
                           :flags_o, :flags_n, :flags_m, :flags_r7,
                           :flags_l, :flags_k, :flags_j, :flags_r8,
                           :flags_h, :flags_r9, :flags_g, :flags_f,
                           :flags_e, :flags_d, :flags_r10, :flags_c,
                           :flags_b, :flags_a
      alias_method :nego56?, :flags_w?
      alias_method :key_exch?, :flags_v?
      alias_method :nego128?, :flags_u?
      alias_method :version?, :flags_t?
      alias_method :target_info?, :flags_s?
      alias_method :non_nt_session_key?, :flags_r?
      alias_method :identify?, :flags_q?
      alias_method :ext_session_security?, :flags_p?
      alias_method :target_type_server?, :flags_o?
      alias_method :target_type_domain?, :flags_n?
      alias_method :always_sign?, :flags_m?
      alias_method :oem_workstation_supplied?, :flags_l?
      alias_method :oem_domain_supplied?, :flags_k?
      alias_method :anonymous?, :flags_j?
      alias_method :ntlm?, :flags_h?
      alias_method :lm_key?, :flags_g?
      alias_method :datagram?, :flags_f?
      alias_method :seal?, :flags_e?
      alias_method :sign?, :flags_d?
      alias_method :request_target?, :flags_c?
      alias_method :oem?, :flags_b?
      alias_method :unicode?, :flags_a?
    end
  end
end

require_relative 'ntlm/negotiate'
#require_relative 'ntlm/challenge'
#require_relative 'ntlm/authenticate'
