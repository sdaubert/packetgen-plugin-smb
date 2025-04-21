# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB
    module Close
      # Close Response.
      #
      # This is a void container. {#word_count} and {#byte_count} should be 0.
      # @author Sylvain Daubert
      # @since 0.3.0
      class Response < PacketGen::Header::Base
        # @!attribute word_count
        #  The size, in 2-byte words, of the SMB command parameters. It should
        #  be +0+.
        #  @return [Integer]
        define_attr :word_count, BinStruct::Int8, default: 3
        define_attr :last_modified, BinStruct::Int32le
        # @!attribute byte_count
        #  Should be 0.
        #  @return [Integer]
        define_attr :byte_count, BinStruct::Int16le, default: 0

        # Give protocol name for this class
        # @return [String]
        def self.protocol_name
          'SMB::Close::Response'
        end
      end
    end
  end
end
