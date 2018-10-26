# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB2
    module SessionSetup
      # SMB2 SessionSetup request structure
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |        StructureSize          |             Flags             |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |        BufferOffset           |           BufferLength        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                        Buffer (variable)                      |
      #   +                                                               +
      #   |                              ...                              |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class Response < Base
        # @!attribute structure_size
        #  16-bit session setup request structure size. Should be 9.
        #  @return [Integer]
        define_field :structure_size, PacketGen::Types::Int16le, default: 9
        # @!attribute flags
        #  16-bit session flags
        #  @return [Integer]
        define_field :flags, PacketGen::Types::Int16le
        # @!attribute flags_rsv
        #  13-bit reserved field
        #  @return [Integer]
        # @!attribute flags_encrypt_data?
        #  @return [Boolean]
        # @!attribute flags_is_null?
        #  @return [Boolean]
        # @!attribute flags_is_guest?
        #  @return [Boolean]
        define_bit_fields_on :flags, :flags_rsv, 13,:flags_encrypt_data, :flags_is_null, :flags_is_guest
        # @!attribute buffer_offset
        #  The offset, from the beginning of the SMB2 header of the {#buffer}.
        #  @return [Integer]
        define_field :buffer_offset, PacketGen::Types::Int16le, default: SMB2::HEADER_SIZE + 8
        # @!attribute buffer_length
        #  The length of the {#buffer} field.
        #  @return [Integer]
        define_field :buffer_length, PacketGen::Types::Int16le
        # @!attribute buffer
        #  @return [GSSAPI]
        define_field :buffer, GSSAPI, token: :response

        # Calculate and set {#buffer_length} field.
        # @return [void]
        def calc_length
          self.buffer_length = buffer.sz
        end

        # Protocol name
        # @return [String]
        def self.protocol_name
          'SMB2::SessionSetup::Response'
        end
      end
    end
  end
end