# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class NTLM
    # NTLM Challenge message
    # @author Sylvain Daubert
    class Authenticate < NTLM
      # void MIC
      VOID_MIC = ([0] * 16).pack('C').freeze

      update_field :type, default: NTLM::TYPES['authenticate']

      # @!attribute lm_response
      #   A LM_RESPONSE or LMV2_RESPONSE structure that contains the computed
      #   LM response to the challenge.
      #   @return [String]
      # @!attribute lm_response_len
      #   16-bit unsigned integer that defines the size in bytes of
      #   {#lm_response} in {#payload}.
      #   @return [Integer]
      # @!attribute lm_response_maxlen
      #   16-bit unsigned integer that should be equal to {#lm_response_len}.
      #   @return [Integer]
      # @!attribute lm_response_offset
      #   A 32-bit unsigned integer that defines the offset, in bytes, from
      #   the beginning of the AUTHENTICATE MESSAGE to {#lm_response} in {#payload}.
      #   @return [Integer]
      define_in_payload :lm_response, PacketGen::Types::String

      # @!attribute nt_response
      #   A NTLM_RESPONSE or NTLMV2_RESPONSE structure that contains the computed
      #   NT response to the challenge.
      #   @return [String]
      # @!attribute nt_response_len
      #   16-bit unsigned integer that defines the size in bytes of
      #   {#nt_response} in {#payload}.
      #   @return [Integer]
      # @!attribute nt_response_maxlen
      #   16-bit unsigned integer that should be equal to {#nt_response_len}.
      #   @return [Integer]
      # @!attribute nt_response_offset
      #   A 32-bit unsigned integer that defines the offset, in bytes, from
      #   the beginning of the AUTHENTICATE MESSAGE to {#nt_response} in {#payload}.
      #   @return [Integer]
      define_in_payload :nt_response, PacketGen::Types::String

      # @!attribute domain_name
      #  Name of the client authentication domain.
      #  @return [String]
      # @!attribute domain_name_len
      #  2-byte {#domain_name} length
      #  @return [Integer]
      # @!attribute domain_name_maxlen
      #  2-byte {#domain_name} max length. Should be equal to {#domain_name_len}.
      #  @return [Integer]
      # @!attribute domain_name_offset
      #  4-byte {#domain_name} offset from  the beginning of the AUTHENTICATE
      #  MESSAGE in {#payload}
      #  @return [Integer]
      define_in_payload :domain_name

      # @!attribute user_name
      #  Name of the user to be authenticated.
      #  @return [String]
      # @!attribute user_name_len
      #  2-byte {#user_name} length
      #  @return [Integer]
      # @!attribute user_name_maxlen
      #  2-byte {#user_name} max length. Should be equal to {#user_name_len}.
      #  @return [Integer]
      # @!attribute user_name_offset
      #  4-byte {#user_name} offset from  the beginning of the AUTHENTICATE
      #  MESSAGE in {#payload}
      #  @return [Integer]
      define_in_payload :user_name

      # @!attribute workstation
      #  Name of the client machine.
      #  @return [String]
      # @!attribute workstation_len
      #  2-byte {#workstation} length
      #  @return [Integer]
      # @!attribute workstation_maxlen
      #  2-byte {#workstation} max length. Should be equal to {#workstation_len}.
      #  @return [Integer]
      # @!attribute workstation_offset
      #  4-byte {#workstation} offset from  the beginning of the AUTHENTICATE
      #  MESSAGE in {#payload}
      #  @return [Integer]
      define_in_payload :workstation

      # @!attribute session_key
      #  The client's encrypted random session key. On
      #  @return [String]
      # @!attribute session_key_len
      #  2-byte {#session_key} length
      #  @return [Integer]
      # @!attribute session_key_maxlen
      #  2-byte {#session_key} max length. Should be equal to {#session_key_len}.
      #  @return [Integer]
      # @!attribute session_key_offset
      #  4-byte {#session_key} offset from  the beginning of the AUTHENTICATE
      #  MESSAGE in {#payload}.
      #  @return [Integer]
      define_in_payload :session_key, PacketGen::Types::String

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

      # @!attribute version
      #  8-byte version information
      #  @return [String]
      define_field_before :payload, :version, PacketGen::Types::String, static_length: 8, default: VOID_VERSION

      # @!attribute mic
      #  16-byte message integrity code
      #  @return [String]
      define_field_before :payload, :mic, PacketGen::Types::String, static_length: 16, default: VOID_MIC
    end
  end
end
