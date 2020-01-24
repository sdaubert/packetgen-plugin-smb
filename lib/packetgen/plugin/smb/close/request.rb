# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB
    module Close
      # Close Request.
      # @author Sylvain Daubert
      # @since 0.3.0
      class Request < PacketGen::Header::Base
        # @!attribute word_count
        #  The size, in 2-byte words, of the SMB command parameters. It should
        #  be +3+.
        #  @return [Integer]
        define_field :word_count, PacketGen::Types::Int8, default: 3
        # @!attribute fid
        #  16-bit FID of the object to close
        #  @return [Integer]
        define_field :fid, PacketGen::Types::Int16le, default: 3
        # @!attribute last_modified
        #  32-bit time value encoded as the number of seconds since January
        #  1, 1970 00:00:00.0. The client can request that the last modification
        #  time for the file be updated to this time value. A value of +0x00000000+
        #  or +0xFFFFFFFF+ results in the server not updating the last modification
        #  time.
        #  @return [Integer]
        define_field :last_modified, PacketGen::Types::Int32le
        # @!attribute byte_count
        #  Should be 0.
        #  @return [Integer]
        define_field :byte_count, PacketGen::Types::Int16le, default: 0

        # Give protocol name for this class
        # @return [String]
        def self.protocol_name
          'SMB::Close::Request'
        end
      end
    end
  end
end
