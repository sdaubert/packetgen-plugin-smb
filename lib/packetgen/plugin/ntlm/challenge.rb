# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class NTLM
    # NTLM Challenge message
    # @author Sylvain Daubert
    class Challenge < NTLM
      update_field :type, default: NTLM::TYPES['challenge']

      # @!attribute target_name
      #   Name of the server authentication realm. Must be expressed in the
      #   negotiated character set.
      #   @return [SMB::String]
      # @!attribute target_name_len
      #   16-bit unsigned integer that defines the size in bytes of
      #   {#target_name} in {#payload}. This field is set only if {#request_target?}
      #   is set.
      #   @return [Integer]
      # @!attribute target_name_maxlen
      #   16-bit unsigned integer that should be equal to {#target_name_len}.
      #   @return [Integer]
      # @!attribute target_name_offset
      #   A 32-bit unsigned integer that defines the offset, in bytes, from
      #   the beginning of the CHALLENGE MESSAGE to {#target_name} in {#payload}.
      #   This field is set only if {#request_target?} is set.
      #   @return [Integer]
      define_in_payload :target_name

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
      # @!attribute oem_target_info_supplied?
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

      # @!attribute challenge
      #   64-bit value containing the NTLM challenge.
      #   @return [String]
      define_field_before :payload, :challenge, PacketGen::Types::String, static_length: 8
      # @!attribute reserved
      #   64-bit reserved field
      #   @return [Integer]
      define_field_before :payload, :reserved, PacketGen::Types::Int64le

      # @!attribute target_info
      #   @return [ArrayOfAvPair]
      # @!attribute target_info_len
      #   16-bit unsigned integer that defines the size in bytes of
      #   {#target_info} in {#payload}. This field is set only if {#target_info?}
      #   is set.
      #   @return [Integer]
      # @!attribute target_info_maxlen
      #   16-bit unsigned integer that should be equal to {#target_info_len}.
      #   @return [Integer]
      # @!attribute target_info_offset
      #   A 32-bit unsigned integer that defines the offset, in bytes, from
      #   the beginning of the CHALLENGE MESSAGE to {#target_info} in {#payload}.
      #   This field is set only if {#target_info?} is set.
      #   @return [Integer]
      define_in_payload :target_info, ArrayOfAvPair

      # @!attribute version
      #  8-byte version information
      #  @return [String]
      define_field_before :payload, :version, PacketGen::Types::String, static_length: 8, default: VOID_VERSION
    end
  end
end
