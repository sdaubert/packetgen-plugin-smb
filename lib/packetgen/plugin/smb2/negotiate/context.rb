# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB2
    module Negotiate
      # NegotiateContext structure.
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |             Type              |           DataLength          |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                           Reserved                            |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                       Data (variable)                         |
      #   +                                                               +
      #   |                              ...                              |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class Context < BinStruct::Struct
        # Known types
        TYPES = {
          'PREAUTH_INTEGRITY_CAP' => 1,
          'ENCRYPTION_CAP' => 2
        }.freeze

        # @!attribute type
        #  16-bit context type
        #  @return [Integer]
        define_attr :type, BinStruct::Int16leEnum, enum: TYPES
        # @!attribute data_length
        #  16-bit data length
        #  @return [Integer]
        define_attr :data_length, BinStruct::Int16le
        # @!attribute reserved
        #  32-bit reserved field
        #  @return [Integer]
        define_attr :reserved, BinStruct::Int32le
        # @!attribute data
        #  context data
        #  @return [String]
        define_attr :data, BinStruct::String, builder: ->(h, t) { t.new(length_from: h[:data_length]) }
        # @!attribute pad
        #  Padding to align next context on a 8-byte offset
        #  @return [String]
        define_attr :pad, BinStruct::String, builder: ->(h, t) { t.new(length_from: -> { 8 - ((h.offset_of(:data) + h.data_length) % 8) }) }

        # @private
        alias old_read read

        # Get human-readable type
        # @return [String]
        def human_type
          self[:type].to_human
        end

        # Get human-readable context
        # @return [String]
        def to_human
          human_type
        end

        # Set {#data_length} field
        # @return [Integer]
        def calc_length
          self[:pad].read SMB2::MAX_PADDING
          self.data_length = sz - self[:pad].sz - 8
        end
      end

      # Specialized {Context} for PREAUTH_INTEGRITY_CAP type.
      class PreauthIntegrityCap < Context
        remove_attr :data
        # @!attribute hash_alg_count
        #  16-bit number of hash algorithm in {#hash_alg}
        #  @return [Integer]
        define_attr_before :pad, :hash_alg_count, BinStruct::Int16le
        # @!attribute salt_length
        #  16-bit length of {#salt} field, in bytes.
        #  @return [Integer]
        define_attr_before :pad, :salt_length, BinStruct::Int16le
        # @!attribute hash_alg
        #  Array of 16-bit integer IDs specifying the supported preauthentication
        #  hash algorithms
        #  @return [BinStruct::ArrayOfInt16le]
        define_attr_before :pad, :hash_alg, BinStruct::ArrayOfInt16le, builder: ->(h, t) { t.new(counter: h[:hash_alg_count]) }
        # @!attribute salt
        #  Salt value for hash
        #  @return [String]
        define_attr_before :pad, :salt, BinStruct::String, builder: ->(h, t) { t.new(length_from: h[:salt_length]) }
        update_attr :pad, builder: ->(h, t) { t.new(length_from: -> { (8 - ((h.offset_of(:salt) + h.salt_length) % 8)) }) }
      end

      # Specialized {Context} for ENCRYPTION_CAP type.
      class EncryptionCap < Context
        remove_attr :data
        # @!attribute cipher_count
        #  16-bit number of cipher algorithm in {#ciphers}
        #  @return [Integer]
        define_attr_before :pad, :cipher_count, BinStruct::Int16le
        # @!attribute ciphers
        #  Array of 16-bit integer IDs specifying the supported encryption
        #  algorithms
        #  @return [BinStruct::ArrayOfInt16le]
        define_attr_before :pad, :ciphers, BinStruct::ArrayOfInt16le, builder: ->(h, t) { t.new(counter: h[:cipher_count]) }
        update_attr :pad, builder: ->(h, t) { t.new(length_from: -> { (8 - ((h.offset_of(:cipher_count) + h[:cipher_count].sz) % 8)) % 8 }) }
      end

      # Array of {Context}
      # @author Sylvain Daubert
      class ArrayOfContext < BinStruct::Array
        set_of Context

        private

        def real_type(ctx)
          name = Context::TYPES.key(ctx.type).to_s
          klassname = name.downcase.capitalize.gsub(/_(\w)/) { $1.upcase }
          if !klassname.empty? && Negotiate.const_defined?(klassname)
            Negotiate.const_get(klassname)
          else
            ctx.class
          end
        end
      end
    end
  end
end
