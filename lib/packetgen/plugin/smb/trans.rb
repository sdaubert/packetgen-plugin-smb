# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB
    # Transaction Request.
    #
    # See also {Blocks}, as {TransRequest} is a specialization of {Blocks#words}
    # and {Blocks#bytes}.
    # @author Sylvain Daubert
    # @since 0.1.0
    class TransRequest < PacketGen::Header::Base
      # @!attribute word_count
      #  The size, in 2-byte words, of the SMB command parameters. It should
      #  be +14 + setup_count+.
      #  @return [Integer]
      define_field :word_count, PacketGen::Types::Int8, default: 14
      # @!attribute total_param_count
      #  The total number of transaction parameter bytes.
      #  @return [Integer]
      define_field :total_param_count, PacketGen::Types::Int16le
      # @!attribute total_data_count
      #  The total number of transaction data bytes.
      #  @return [Integer]
      define_field :total_data_count, PacketGen::Types::Int16le
      # @!attribute max_param_count
      #  The maximum number of parameter bytes that the client will accept
      #  in transaction response.
      #  @return [Integer]
      define_field :max_param_count, PacketGen::Types::Int16le
      # @!attribute max_data_count
      #  The maximum number of data bytes that the client will accept
      #  in transaction response.
      #  @return [Integer]
      define_field :max_data_count, PacketGen::Types::Int16le
      # @!attribute max_setup_count
      #  The maximum number of setup bytes that the client will accept
      #  in transaction response.
      #  @return [Integer]
      define_field :max_setup_count, PacketGen::Types::Int8
      # @!attribute rsv1
      #  8-bit reserved field
      #  @return [Integer]
      define_field :rsv1, PacketGen::Types::Int8, default: 0
      # @!attribute flags
      #  16-bit flags
      #  @return [Integer]
      define_field :flags, PacketGen::Types::Int16le
      # @!attribute timeout
      #  32-bit timeout
      #  @return [Integer]
      define_field :timeout, PacketGen::Types::Int32le
      # @!attribute rsv2
      #  16-bit reserved field
      #  @return [Integer]
      define_field :rsv2, PacketGen::Types::Int16le, default: 0
      # @!attribute param_count
      #  16-bit number of transaction parameter bytes that the clients attempts to
      #  send to the server in this request.
      #  @return [Integer]
      define_field :param_count, PacketGen::Types::Int16le
      # @!attribute param_offset
      #  16-bit offset (in bytes) from the start of the SMB header to the start of the
      #  transaction parameters.
      #  @return [Integer]
      define_field :param_offset, PacketGen::Types::Int16le
      # @!attribute data_count
      #  16-bit number of transaction data bytes that the clients sends to
      #  the server in this request.
      #  @return [Integer]
      define_field :data_count, PacketGen::Types::Int16le
      # @!attribute data_offset
      #  16-bit offset (in bytes) from the start of the SMB header to the start
      #  of the data field.
      #  @return [Integer]
      define_field :data_offset, PacketGen::Types::Int16le
      # @!attribute setup_count
      #  8-bit number of setup words (ie 16-bit words) contained in {#setup} field.
      define_field :setup_count, PacketGen::Types::Int8
      # @!attribute rsv3
      #  8-bit reserved field
      #  @return [Integer]
      define_field :rsv3, PacketGen::Types::Int8
      # @!attribute setup
      #  Array of 2-byte words.
      #  @return [Array]
      define_field :setup, PacketGen::Types::ArrayOfInt16le, builder: ->(h, t) { t.new(counter: h[:setup_count]) }
      # @!attribute byte_count
      #  @return [Integer]
      define_field :byte_count, PacketGen::Types::Int16le
      # @!attribute padname
      #  8-bit optional padding to align {#name} on a 2-byte boundary. Only present
      #  if {SMB#flags2_unicode?} is +true+.
      #  @return [Integer]
      define_field :padname, PacketGen::Types::Int8, optional: ->(h) { h.packet && h.packet.smb.flags2_unicode? }
      # @!attribute name
      #  Pathname of the mailslot or named pipe.
      #  @return [String]
      define_field :name, SMB::String, builder: ->(h, t) { t.new(unicode: !h.packet || h.packet.smb.flags2_unicode?) }
      # @!attribute pad1
      #  Padding to align {#body} on 4-byte boundary.
      #  @return [String]
      define_field :pad1, PacketGen::Types::String, default: "\0" * 4,
                   builder: ->(h, t) { t.new(length_from: -> { h.data_offset - SMB.new.sz - (h.offset_of(:name) + h[:name].sz) }) }
      define_field :body, PacketGen::Types::String

      # Give protocol name for this class
      # @return [String]
      def protocol_name
        'SMB::TransRequest'
      end
    end

    # Transaction Response.
    #
    # See also {Blocks}, as {TransResponse} is a specialization of {Blocks#words}
    # and {Blocks#bytes}.
    # @author Sylvain Daubert
    # @since 0.1.0
    class TransResponse < PacketGen::Header::Base
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
      define_field :body, PacketGen::Types::String

      # Give protocol name for this class
      # @return [String]
      def protocol_name
        'SMB::TransResponse'
      end
    end

    self.bind_command 'trans'
  end
end
