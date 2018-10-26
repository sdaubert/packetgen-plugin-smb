# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB
    module Trans
      # Transaction Response.
      #
      # See also {Blocks}, as {Response} is a specialization of {Blocks#words}
      # and {Blocks#bytes}.
      # @author Sylvain Daubert
      class Response < PacketGen::Header::Base
        # @!attribute word_count
        #  The size, in 2-byte words, of the SMB command parameters. It should
        #  be +14 + setup_count+.
        #  @return [Integer]
        define_field :word_count, PacketGen::Types::Int8, default: 10
        # @!attribute total_param_count
        #  The total number of transaction parameter bytes.
        #  @return [Integer]
        define_field :total_param_count, PacketGen::Types::Int16le
        # @!attribute total_data_count
        #  The total number of transaction data bytes.
        #  @return [Integer]
        define_field :total_data_count, PacketGen::Types::Int16le
        # @!attribute rsv1
        #  16-bit reserved field
        #  @return [Integer]
        define_field :rsv1, PacketGen::Types::Int16le, default: 0
        # @!attribute param_count
        #  16-bit number of transaction parameter bytes sent in this response.
        #  @return [Integer]
        define_field :param_count, PacketGen::Types::Int16le
        # @!attribute param_offset
        #  16-bit offset (in bytes) from the start of the SMB header to the start of the
        #  transaction parameters.
        #  @return [Integer]
        define_field :param_offset, PacketGen::Types::Int16le
        # @!attribute param_displacement
        #  16-bit offset (in bytes) relative to all of the transaction
        #  parameter bytes in this transaction response at which this block of
        #  parameter bytes SHOULD be placed.
        #  @return [Integer]
        define_field :param_displacement, PacketGen::Types::Int16le
        # @!attribute data_count
        #  16-bit number of transaction data bytes sent in this response.
        #  @return [Integer]
        define_field :data_count, PacketGen::Types::Int16le
        # @!attribute data_offset
        #  16-bit offset (in bytes) from the start of the SMB header to the start
        #  of the data field.
        #  @return [Integer]
        define_field :data_offset, PacketGen::Types::Int16le
        # @!attribute data_displacement
        #  16-bit offset (in bytes) relative to all of the transaction data bytes in
        #  this transaction response at which this block of data bytes SHOULD be placed.
        #  @return [Integer]
        define_field :data_displacement, PacketGen::Types::Int16le
        # @!attribute setup_count
        #  8-bit number of setup words (ie 16-bit words) contained in {#setup} field.
        define_field :setup_count, PacketGen::Types::Int8
        # @!attribute rsv3
        #  8-bit reserved field
        #  @return [Integer]
        define_field :rsv2, PacketGen::Types::Int8
        # @!attribute setup
        #  Array of 2-byte words.
        #  @return [ArrayPacketGen::]
        define_field :setup, PacketGen::Types::ArrayOfInt16le, builder: ->(h, t) { t.new(counter: h[:setup_count]) }
        # @!attribute byte_count
        #  @return [Integer]
        define_field :byte_count, PacketGen::Types::Int16le
        # @!attribute pad1
        #  Padding before {#body} to align it on 32-bit boundary
        #  @return [Integer]
        define_field :pad1, PacketGen::Types::String, default: "\0" * 4,
                     builder: ->(h, t) { t.new(length_from: -> { h.data_offset - SMB.new.sz - (h.offset_of(:byte_count) + h[:byte_count].sz) }) }
        # @!attribute body
        #  @return [String]
        define_field :body, PacketGen::Types::String

        # Give protocol name for this class
        # @return [String]
        def self.protocol_name
          'SMB::Trans::Response'
        end
      end
    end
  end
end
