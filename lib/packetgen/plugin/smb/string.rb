# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB
    # SMB strings (UTF-16 little-endian).
    # @author Sylvain Daubert
    class String < PacketGen::Types::CString
      # @param [Boolean, Proc] is string UTF-16 encoded?
      # @param [Hash] options
      # @option options [Integer] :static_length set a static length for this string
      def initialize(options={})
        super
        self.encode!('UTF-16LE')
      end

      # @param [::String] str
      # @return [String] self
      def read(str)
        return self if str.nil?

        str2 = case str.encoding
               when Encoding::BINARY
                 binidx = nil
                 0.step(to: str.size, by: 2) do |i|
                   binidx = i if str[i, 2] == "\x00\x00"
                 end
                 s = if binidx.nil?
                       str
                     else
                       str[0, binidx]
                     end
                 s.force_encoding('UTF-16LE')
               when Encoding::UTF_16LE
                 str
               else
                 str.encode('UTF-16LE')
               end
        str2 = str2[0, @static_length / 2] if @static_length.is_a? Integer
        idx = str2.index(+"\x00".encode('UTF-16LE'))
        str2 = str2[0, idx] unless idx.nil?
        self.replace str2
        self
      end
    end
  end
end
