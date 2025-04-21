# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB
    module Trans
      # Transaction Request.
      #
      # See also {Blocks}, as {Trans::Request} is a specialization of {Blocks#words}
      # and {Blocks#bytes}.
      # @author Sylvain Daubert
      class Request < PacketGen::Header::Base
        # @!attribute word_count
        #  The size, in 2-byte words, of the SMB command parameters. It should
        #  be +14 + setup_count+.
        #  @return [Integer]
        define_attr :word_count, BinStruct::Int8, default: 14
        # @!attribute total_param_count
        #  The total number of transaction parameter bytes.
        #  @return [Integer]
        define_attr :total_param_count, BinStruct::Int16le
        # @!attribute total_data_count
        #  The total number of transaction data bytes.
        #  @return [Integer]
        define_attr :total_data_count, BinStruct::Int16le
        # @!attribute max_param_count
        #  The maximum number of parameter bytes that the client will accept
        #  in transaction response.
        #  @return [Integer]
        define_attr :max_param_count, BinStruct::Int16le
        # @!attribute max_data_count
        #  The maximum number of data bytes that the client will accept
        #  in transaction response.
        #  @return [Integer]
        define_attr :max_data_count, BinStruct::Int16le
        # @!attribute max_setup_count
        #  The maximum number of setup bytes that the client will accept
        #  in transaction response.
        #  @return [Integer]
        define_attr :max_setup_count, BinStruct::Int8
        # @!attribute rsv1
        #  8-bit reserved field
        #  @return [Integer]
        define_attr :rsv1, BinStruct::Int8, default: 0
        # @!attribute flags
        #  16-bit flags
        #  @return [Integer]
        define_attr :flags, BinStruct::Int16le
        # @!attribute timeout
        #  32-bit timeout
        #  @return [Integer]
        define_attr :timeout, BinStruct::Int32le
        # @!attribute rsv2
        #  16-bit reserved field
        #  @return [Integer]
        define_attr :rsv2, BinStruct::Int16le, default: 0
        # @!attribute param_count
        #  16-bit number of transaction parameter bytes that the clients attempts to
        #  send to the server in this request.
        #  @return [Integer]
        define_attr :param_count, BinStruct::Int16le
        # @!attribute param_offset
        #  16-bit offset (in bytes) from the start of the SMB header to the start of the
        #  transaction parameters.
        #  @return [Integer]
        define_attr :param_offset, BinStruct::Int16le
        # @!attribute data_count
        #  16-bit number of transaction data bytes that the clients sends to
        #  the server in this request.
        #  @return [Integer]
        define_attr :data_count, BinStruct::Int16le
        # @!attribute data_offset
        #  16-bit offset (in bytes) from the start of the SMB header to the start
        #  of the data field.
        #  @return [Integer]
        define_attr :data_offset, BinStruct::Int16le
        # @!attribute setup_count
        #  8-bit number of setup words (ie 16-bit words) contained in {#setup} field.
        define_attr :setup_count, BinStruct::Int8
        # @!attribute rsv3
        #  8-bit reserved field
        #  @return [Integer]
        define_attr :rsv3, BinStruct::Int8
        # @!attribute setup
        #  Array of 2-byte words.
        #  @return [Array]
        define_attr :setup, BinStruct::ArrayOfInt16le, builder: ->(h, t) { t.new(counter: h[:setup_count]) }
        # @!attribute byte_count
        #  @return [Integer]
        define_attr :byte_count, BinStruct::Int16le
        # @!attribute padname
        #  8-bit optional padding to align {#name} on a 2-byte boundary. Only present
        #  if {SMB#flags2_unicode?} is +true+.
        #  @return [Integer]
        define_attr :padname, BinStruct::Int8, optional: ->(h) { h&.packet&.smb&.flags2_unicode? } # rubocop:disable Style/SafeNavigationChainLength
        # @!attribute name
        #  Pathname of the mailslot or named pipe.
        #  @return [String]
        define_attr :name, SMB::String, builder: ->(h, t) { t.new(unicode: !h.packet || h.packet.smb.flags2_unicode?) }
        # @!attribute pad1
        #  Padding to align {#body} on 4-byte boundary.
        #  @return [String]
        define_attr :pad1, BinStruct::String,
                    default: "\0" * 4,
                    builder: ->(h, t) { t.new(length_from: -> { h.data_offset - SMB.new.sz - (h.offset_of(:name) + h[:name].sz) }) }
        # @!attribute body
        #  @return [String]
        define_attr :body, BinStruct::String

        # Give protocol name for this class
        # @return [String]
        def self.protocol_name
          'SMB::Trans::Request'
        end
      end
    end
  end
end
