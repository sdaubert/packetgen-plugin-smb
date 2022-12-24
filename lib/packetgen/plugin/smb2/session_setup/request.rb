# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB2
    module SessionSetup
      # SMB2 SessionSetup request structure
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |        StructureSize          |     Flags     |  SecurityMode |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                         Capabilities                          |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                            Channel                            |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |        BufferOffset           |           BufferLength        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                       PreviousSessionId                       |
      #   +                                                               +
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                        Buffer (variable)                      |
      #   +                                                               +
      #   |                              ...                              |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class Request < Base
        # Security modes
        SECURITY_MODES = Negotiate::Request::SECURITY_MODES

        # @!attribute structure_size
        #  16-bit session setup request structure size. Should be 25.
        #  @return [Integer]
        define_field :structure_size, PacketGen::Types::Int16le, default: 25
        # @!attribute flags
        #  8-bit flags for SMB 3 dialect.
        #  @return [Integer]
        define_field :flags, PacketGen::Types::Int8
        # @!attribute flags_rsv
        #  @return [Integer]
        # @!attribute flags_binding?
        #  @return [Boolean]
        define_bit_fields_on :flags, :flags_rsv, 7, :flags_binding
        # @!attribute security_mode
        #  16-bit security mode field.
        #  @return [Integer]
        define_field :security_mode, PacketGen::Types::Int8Enum, enum: SECURITY_MODES
        # @!attribute capabilities
        #  32-bit capabilities field.
        #  @return [Integer]
        define_field :capabilities, PacketGen::Types::Int32le
        # @!attribute cap_rsv
        #  31-bit reserved field
        #  @return [Boolean]
        # @!attribute cap_dfs
        #  Indicates if Distributed File system (DFS) is supported
        #  @return [Boolean]
        define_bit_fields_on :capabilities, :cap_rsv, 31, :cap_dfs
        # @!attribute channel
        #  32-bit reserved field
        #  @return [Integer]
        define_field :channel, PacketGen::Types::Int32le
        # @!attribute buffer_offset
        #  The offset, from the beginning of the SMB2 header of the {#buffer}.
        #  @return [Integer]
        define_field :buffer_offset, PacketGen::Types::Int16le, default: SMB2::HEADER_SIZE + (6 * 4)
        # @!attribute buffer_length
        #  The length of the {#buffer} field.
        #  @return [Integer]
        define_field :buffer_length, PacketGen::Types::Int16le
        # @!attribute prev_session_id
        #  64-bit previously established session id
        #  @return [Integer]
        define_field :prev_session_id, PacketGen::Types::Int64le
        # @!attribute buffer
        #  @return [GSSAPI]
        define_field :buffer, GSSAPI, token: :response, optional: ->(h) { h.buffer_offset.positive? }

        # Calculate and set {#buffer_length} and {#buffer_offset} fields.
        # @return [void]
        def calc_length
          self.buffer_length = self[:buffer].sz
          self.buffer_offset = if self.buffer_length.zero?
                                 0
                               else
                                 SMB2.new.sz + offset_of(:buffer)
                               end
        end

        # Protocol name
        # @return [String]
        def self.protocol_name
          'SMB2::SessionSetup::Request'
        end
      end
    end
  end
end
