# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB
    # Common blocks used for unsupported SMB messages.
    #
    # {Blocks} handles parameter block and data block. Parameter block is
    # composed of:
    # * a 8-bit {#word_count} field,
    # * a {#words} field, an array of {Types::Int16le}.
    # Data block is composed of:
    # * a little endian 16-bit {#byte_count} field,
    # * a {#bytes} field, an array of {Types::Int8}.
    # @author Sylvain Daubert
    class Blocks < PacketGen::Header::Base
      # @!attribute word_count
      #  The size, in 2-byte words, of the {#words} field.
      #  @return [Integer]
      define_field :word_count, PacketGen::Types::Int8
      # @!attribute words
      #  The message-specific parameters structure.
      #  @return [PacketGen::Types::ArrayOfInt16le]
      define_field :words, PacketGen::Types::ArrayOfInt16le, builder: ->(h, t) { t.new(counter: h[:word_count]) }
      # @!attribute byte_count
      #  The size, in bytes, of the {#bytes} field.
      #  @return [Integer]
      define_field :byte_count, PacketGen::Types::Int16le
      # @!attribute bytes
      #  The message-specific data structure.
      #  @return [PacketGen::Types::ArrayOfInt8]
      define_field :bytes, PacketGen::Types::ArrayOfInt8, builder: ->(h, t) { t.new(counter: h[:byte_count]) }

      # Give protocol name for this class
      # @return [String]
      def protocol_name
        'SMB::Blocks'
      end
    end
  end
  PacketGen::Header.add_class SMB::Blocks
  SMB.bind SMB::Blocks
end
