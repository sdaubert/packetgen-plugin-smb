# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB
    module Negotiate
      # SMB Negotiation Request header.
      #
      # See also {Blocks}, as {Negotiate::Request} is a specialization of {Blocks#words}
      # and {Blocks#bytes}.
      # @author Sylvain Daubert
      class Request < PacketGen::Header::Base
        # @!attribute word_count
        #  The size, in 2-byte words, of the SMB command parameters. It should
        #  be +0+ setup_count+.
        #  @return [Integer]
        define_field :word_count, PacketGen::Types::Int8, default: 0
        # @!attribute byte_count
        #  @return [Integer]
        define_field :byte_count, PacketGen::Types::Int16le
        # @!attribute dialects
        #  @return [ArrayOfDialect]
        define_field :dialects, ArrayOfDialect

        def self.protocol_name
          'SMB::Negotiate::Request'
        end
      end
    end
  end
end
