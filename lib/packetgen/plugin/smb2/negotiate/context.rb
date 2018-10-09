# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB2
    module Negotiate
      # NegotiateContext structure.
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |             Type              |           DataLength          |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                           Reserved                            |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                       Data (variable)                         |
      #   +                                                               +
      #   |                              ...                              |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class Context < PacketGen::Types::Fields
        # Known types
        TYPES = {
          'PREAUTH_INTEGRITY_CAP' => 1,
          'ENCRYPTION_CAP' => 2
        }

        # @!attribute type
        #  16-bit context type
        #  @return [Integer]
        define_field :type, PacketGen::Types::Int16leEnum, enum: TYPES
        # @!attribute data_length
        #  16-bit data length
        #  @return [Integer]
        define_field :data_length, PacketGen::Types::Int16le
        # @!attribute reserved
        #  32-bit reserved field
        #  @return [Integer]
        define_field :reserved, PacketGen::Types::Int32le
        # @!attribute data
        #  context data
        #  @return [String]
        define_field :data, PacketGen::Types::String, builder: ->(h, t) { t.new(length_from: h[:data_length]) }
        # @!attribute pad
        #  Padding to align next context on a 8-byte offset
        #  @return [String]
        define_field :pad, PacketGen::Types::String, builder: ->(h, t) { t.new(length_from: -> { v = 8 - (h.offset_of(:data) + h.data_length) % 8; v == 8 ? 0 : v }) }

        # Get human-readable type
        # @return [String]
        def human_type
          self[:type].to_human
        end

        # Get human-readable context
        # @return [String]
        def to_human
          human_type
        end
      end

      class PreauthIntegrityCap < Context
      end

      # Array of {NegotiateContext}
      # @author Sylvain Daubert
      class ArrayOfContext < PacketGen::Types::Array
        set_of Context
      end
    end
  end
end