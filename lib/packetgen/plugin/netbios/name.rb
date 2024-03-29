# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  # Module to group all NetBIOS headers
  # @author Sylvain Daubert
  module NetBIOS
    # NetBIOS Name.
    # @author Sylvain Daubert
    class Name < PacketGen::Header::DNS::Name
      # Size, in bytes, of an encoded NetBIOS name
      ENCODED_NAME_SIZE = 32

      # Read a NetBIOS name from a string
      # @param [String] str
      # @return [Name] self
      def from_human(str)
        clear
        return self if str.nil?

        encoded_name = encode_name(str)
        super(encoded_name)
      end

      # Get a human readable string
      # @return [String]
      def to_human
        encoded_name = super
        decode_name(encoded_name)
      end

      private

      def encode_name(name)
        basename, *scope_id = name.split('.')
        basename ||= ''
        scope_id = scope_id.join('.')
        encoded_name = +''
        basename.each_byte do |byte|
          a = (byte >> 4) + 0x41
          b = (byte & 0xf) + 0x41
          encoded_name << [a, b].pack('C2')
        end
        encoded_name << ('CA' * ((ENCODED_NAME_SIZE - encoded_name.size) / 2)) if encoded_name.size < ENCODED_NAME_SIZE
        encoded_name << ".#{scope_id}" if scope_id
        encoded_name
      end

      def decode_name(encoded_name)
        name = +''
        encoded_name.partition('.').first.scan(/../).map do |duo|
          a = (duo[0].ord - 0x41) & 0xf
          b = (duo[1].ord - 0x41) & 0xf
          name << ((a << 4) | b).chr
        end
        name.strip
      end
    end
  end
end
