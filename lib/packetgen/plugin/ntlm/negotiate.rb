# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class NTLM
    # NTLM Negotiate message
    # @author Sylvain Daubert
    class Negotiate < NTLM
      # @return [String]
      attr_accessor :domain_name
      # @return [String]
      attr_accessor :workstation

      update_field :type, default: NTLM::TYPES['negotiate']
      # @!attribute flags
      #   Negotiate flags
      #   @return [Integer]

      # @!group Negotiate flags
      # @!attribute nego56?
      #   Also known as +flags_w?+.
      #   @return [Boolean]
      # @!attribute key_exch?
      #   Also known as +flags_v?+
      #   @return [Boolean]
      # @!attribute nego128?
      #   Also known as +flags_u?+
      #   @return [Boolean]
      # @!attribute version?
      #   Also known as +flags_t+
      #   @return [Integer]
      # @!attribute target_info?
      #   Also known as +flags_s?+
      #   @return [Boolean]
      # @!attribute non_nt_session_key?
      #   Also known as +flags_r?+
      #   @return [Boolean]
      # @!attribute identify?
      #   Also known as +flags_q+
      #   @return [Boolean]
      # @!attribute ext_session_security?
      #   Also known as +flags_p?+
      #   @return [Boolean]
      # @!attribute target_type_server?
      #   Also known as +flags_o?+
      #   @return [Boolean]
      # @!attribute target_type_domain?
      #   Also known as +flags_n?+
      #   @return [Boolean]
      # @!attribute always_sign?
      #   Also known as +flags_m?+
      #   @return [Boolean]
      # @!attribute oem_workstation_supplied?
      #   Also known as +flags_l?+
      #   @return [Boolean]
      # @!attribute oem_domain_supplied?
      #   Also known as +flags_k?+
      #   @return [Boolean]
      # @!attribute anonymous?
      #   Also known as +flags_j?+
      #   @return [Boolean]
      # @!attribute ntlm?
      #   Also known as +flags_h?+
      #   @return [Boolean]
      # @!attribute lm_key?
      #   Also known as +flags_g?+
      #   @return [Boolean]
      # @!attribute datagram?
      #   Also known as +flags_f?+
      #   @return [Boolean]
      # @!attribute seal?
      #   Also known as +flags_e?+
      #   @return [Boolean]
      # @!attribute sign?
      #   Also known as +flags_d?+
      #   @return [Boolean]
      # @!attribute request_target?
      #   Also known as +flags_c?+
      #   @return [Boolean]
      # @!attribute oem?
      #   Also known as +flags_b?+
      #   @return [Boolean]
      # @!attribute unicode?
      #   Also known as +flags_a?+
      #   @return [Boolean]
      define_negotiate_flags
      # @!endgroup Negotiate flags

      # @!attribute domain_name
      #  Name of the client authentication domain. Must be OEM encoded.
      #  @return [PacketGen::Types::String]
      # @!attribute domain_name_len
      #  2-byte domain name length
      #  @return [Integer]
      # @!attribute domain_name_maxlen
      #  2-byte domain name max length
      #  @return [Integer]
      # @!attribute domain_name_offset
      #  4-byte domain name offset
      #  @return [Integer]
      define_in_payload :domain_name, PacketGen::Types::String

      # @!attribute workstation
      #  Name of the client machine. Must be OEM encoded.
      #  @return [PacketGen::Types::String]
      # @!attribute workstation_len
      #  2-byte workstation length
      #  @return [Integer]
      # @!attribute workstation_maxlen
      #  2-byte workstation max length
      #  @return [Integer]
      # @!attribute workstation_offset
      #  4-byte workstation offset
      #  @return [Integer]
      define_in_payload :workstation, PacketGen::Types::String

      # @!attribute version
      #  8-byte version information
      #  @return [String]
      define_field_before :payload, :version, PacketGen::Types::String, static_length: 8, default: VOID_VERSION
    end
  end
end
