# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB2
    # SMB2 Error response structure
    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |        StructureSize          | ContextCount  |    Reserved   |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                          ByteCount                            |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                           ErrorData                           |
    #   +                                                               +
    #   |                              ...                              |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # @author Sylvain Daubert
    class ErrorResponse < PacketGen::Header::Base
      # @!attribute structure_size
      #  16-bit error response structure. Should be 9.
      #  @return [Integer]
      define_attr :structure_size, BinStruct::Int16le, default: 9
      # !@attribute context_count
      #  Only for SMB3 dialect. If non zero, this is the number of element
      #  in {#data}, formatted as a variable length array.
      #  @return [Integer]
      define_attr :context_count, BinStruct::Int8
      # !@attribute reserved
      #  8-bit reserved value
      #  @return [Integer]
      define_attr :reserved, BinStruct::Int8
      # @!attribute byte_count
      #  32-bit value indicating the number of bytes contained in {#data}
      #  @return [Integer]
      define_attr :byte_count, BinStruct::Int32le
      # @!attribute data
      #  Variable-length data field.
      #  @return [String]
      define_attr :data, BinStruct::String
    end
  end
  PacketGen::Header.add_class SMB2::ErrorResponse
  SMB2.bind SMB2::ErrorResponse, status: lambda(&:positive?)
end
