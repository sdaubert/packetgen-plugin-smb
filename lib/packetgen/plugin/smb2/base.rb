# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

require_relative 'guid'

module PacketGen::Plugin
  class SMB2
    # Helper class to ease definition of SMB2 classes
    # @author Sylvain Daubert
    class Base < PacketGen::Header::Base
      # Helper to define pad fields used to align next field on 8-byte
      # offset
      # @param [Symbol] name name of padding field
      # @return [void]
      def self.define_smb2_pad_field(name)
        prev_field = self.fields.last
        lf = lambda do |hdr|
          len = 8 - (hdr.offset_of(prev_field) + hdr[prev_field].sz) % 8
          len = 0 if len == 8
          len
        end
        define_field name, PacketGen::Types::String, default: [0].pack('q').freeze,
                     builder: ->(h, t) { t.new(length_from: -> { lf[h] }) }
      end
    end
  end
end