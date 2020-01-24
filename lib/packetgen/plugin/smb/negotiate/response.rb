# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB
    module Negotiate
      # SMB Negotiation Response header.
      #
      # See also {Blocks}, as {Negotiate::Response} is a specialization of {Blocks#words}
      # and {Blocks#bytes}.
      # @author Sylvain Daubert
      class Response < Blocks
        # Get index of the dialect selected by the server from the list presented in the request.
        # @return [Integer]
        def dialect_index
          words.first.to_i
        end

        def self.protocol_name
          'SMB::Negotiate::Response'
        end
      end
    end
  end
end
