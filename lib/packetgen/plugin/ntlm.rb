# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  # Base class for NTLM authentication protocol.
  # @author Sylvain Daubert
  class NTLM < BinStruct::Struct
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
    VOID_CHALLENGE = VOID_VERSION

    # @!attribute signature
    #  8-byte NTLM signature
    #  @return [String]
    define_attr :signature, BinStruct::String, static_length: 8, default: SIGNATURE
    # @!attribute type
    #  4-byte message type
    #  @return [Integer]
    define_attr :type, BinStruct::Int32leEnum, enum: TYPES
    # @!attribute payload
    #  @return [String]
    define_attr :payload, BinStruct::String

    class << self
      # @api private
      # Return fields defined in payload one.
      # @return [Hash]
      attr_accessor :payload_fields

      # Create a NTLM object from a binary string
      # @param [String] str
      # @return [NTLM]
      def read(str)
        ntlm = self.new.read(str)
        type = TYPES.key(ntlm.type)
        return ntlm if type.nil?

        klass = NTLM.const_get(type.capitalize)
        klass.new.read(str)
      end

      # Define a flags field.
      # @return [void]
      def define_negotiate_flags # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
        define_bit_attr_before :payload, :flags, endian: :little, flags_w: 1, flags_v: 1, flags_u: 1, flags_r13: 3,
                                                 flags_t: 1, flags_r4: 1, flags_s: 1, flags_r: 1,
                                                 flags_r5: 1, flags_q: 1, flags_p: 1, flags_r6: 1,
                                                 flags_o: 1, flags_n: 1, flags_m: 1, flags_r7: 1,
                                                 flags_l: 1, flags_k: 1, flags_j: 1, flags_r8: 1,
                                                 flags_h: 1, flags_r9: 1, flags_g: 1, flags_f: 1,
                                                 flags_e: 1, flags_d: 1, flags_r10: 1, flags_c: 1,
                                                 flags_b: 1, flags_a: 1
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
        alias_method :old_flags_a=, :flags_a=
        alias_method :old_flags=, :flags=

        class_eval do
          def flags_a=(value)
            self.old_flags_a = value
            self.class.payload_fields.each_key do |name|
              attr = send(name)
              attr.unicode = value if attr.respond_to?(:unicode=)
            end

            value
          end

          def flags=(value)
            self.old_flags = value
            self.flags_a = value & 1
          end
        end
      end

      # Define a field in payload. Also add +name_len+, +name_maxlen+ and
      # +name_offset+ fields.
      # @param [Symbol] name name of field.
      # @param [Class,nil] type type of +name+ field.
      # @param [Hash] options type's options needed at build time
      # @return [void]
      def define_in_payload(name, type=SMB::String, options={})
        @payload_fields ||= {}
        @payload_fields[name] = [type, options]

        define_attr_before :payload, :"#{name}_len", BinStruct::Int16le
        define_attr_before :payload, :"#{name}_maxlen", BinStruct::Int16le
        define_attr_before :payload, :"#{name}_offset", BinStruct::Int32le

        attr_accessor name
      end
    end

    # @abstract This method is meaningful for {NTLM} subclasses only.
    def initialize(options={})
      super
      return if self.class.payload_fields.nil?

      self.class.payload_fields.each do |name, type_and_opt|
        type, options = type_and_opt
        content = if type.new.respond_to?(:unicode?)
                    type.new(options.merge(unicode: unicode?))
                  else
                    type.new(options)
                  end
        send(:"#{name}=", content)
      end
    end

    # @abstract This class is meaningful for {NTLM} subclasses only.
    # Populate object from a binary string
    # @param [String] str
    # @return [self]
    def read(str) # rubocop:disable Metrics/AbcSize
      super
      return self if self.class.payload_fields.nil?

      self.class.payload_fields.each do |name, type_and_opt|
        type, options = type_and_opt
        offset_in_payload = send(:"#{name}_offset") - offset_of(:payload)
        length = send(:"#{name}_len")
        content = if type.new.respond_to?(:unicode?)
                    type.new(options.merge(unicode: unicode?))
                  else
                    type.new(options)
                  end
        content.read(payload[offset_in_payload, length]) if length.positive?
        send(:"#{name}=", content)
      end

      self
    end

    # @abstract This class is meaningful for {NTLM} subclasses only.
    # Calculate and set +len+, +maxlen+ and +offset+ fields defined for
    # fields in {#payload}.
    # @return [void]
    def calc_length
      return self if self.class.payload_fields.nil?

      previous_len = 0
      self.class.payload_fields.each_key do |name|
        send(:"#{name}_len=", 0)
        send(:"#{name}_offset=", offset_of(:payload) + previous_len)

        field = send(name)
        next unless field && !field.empty?

        length = field.respond_to?(:sz) ? field.sz : field.size
        send(:"#{name}_len=", length)
        send(:"#{name}_maxlen=", length)
        previous_len = length
      end
    end

    # @abstract This class is meaningful for {NTLM} subclasses only.
    # @return [String]
    def to_s
      s = super
      return s if self.class.payload_fields.nil?

      self.class.payload_fields.each_key do |name|
        attr = send(name)
        attr.unicode = unicode? if attr.respond_to?(:unicode=)
        s << attr.to_s unless attr.nil? || send("#{name}_len").zero?
      end
      s
    end
  end
end

require_relative 'ntlm/av_pair'
require_relative 'ntlm/ntlmv2_response'
require_relative 'ntlm/negotiate'
require_relative 'ntlm/challenge'
require_relative 'ntlm/authenticate'
