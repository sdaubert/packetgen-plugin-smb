# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB2
    # GUID, also known as UUID, is a 16-byte structure, intended to serve
    # as a unique identifier for an object.
    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                             Data1                             |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |            Data2              |             Data3             |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                             Data4                             |
    #   +                                                               +
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # @author Sylvain Daubert
    class GUID < PacketGen::Types::Fields
      include PacketGen::Types::Fieldable

      # @!attribute data1
      #  32-bit little-endian data1
      #  @return [Integer]
      define_field :data1, PacketGen::Types::Int32le
      # @!attribute data2
      #  16-bit little-endian data2
      #  @return [Integer]
      define_field :data2, PacketGen::Types::Int16le
      # @!attribute data3
      #  16-bit little-endian data3
      #  @return [Integer]
      define_field :data3, PacketGen::Types::Int16le
      # @!attribute data4
      #  64-bit big-endian data4
      #  @return [Integer]
      define_field :data4, PacketGen::Types::Int64

      # Get a human-readable GUID, as specified in RFC 4122
      #   guid.to_human  # => "7aedb437-01b9-41d4-a5f7-9e6c06e16c8a"
      # @return [String]
      def to_human
        data4p1 = data4 >> 48
        data4p2 = data4 & 0xffff_ffff_ffff
        '%08x-%04x-%04x-%04x-%012x' % [data1, data2, data3, data4p1, data4p2] # rubocop:disable Style/FormatStringToken
      end

      # Set GUID from a human-readable string
      # @param [String] guid
      # @return [self]
      def from_human(guid)
        return self if guid.nil? || guid.empty?

        values = guid.split('-').map { |v| v.to_i(16) }
        return self if values.size != 5

        self.data1 = values[0]
        self.data2 = values[1]
        self.data3 = values[2]
        self.data4 = values[3] << 48 | values[4]
        self
      end
    end
  end
end
