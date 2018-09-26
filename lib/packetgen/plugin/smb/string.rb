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
      # @param [Boolean] unicode
      attr_writer :unicode

      # @param [Boolean, Proc] is string UTF-16 encoded?
      # @param [Hash] options
      # @option options [Integer] :static_length set a static length for this string
      # @option options [Boolean] :unicode If +true+, string is encoded as a UTF-16
      #    unicode string. If +false+, string is encode in ASCII. Defaults to +true+.
      def initialize(options={})
        super
        @unicode = options.key?(:unicode) ? options[:unicode] : true
        self.encode!('UTF-16LE') if @unicode
        self.encode!('ASCII-8BIT') unless @unicode
      end

      # @return [Boolean]
      def unicode?
        @unicode
      end

      # @param [::String] str
      # @return [String] self
      def read(str)
        return self if str.nil?

        str2 = case str.encoding
               when Encoding::BINARY
                 binidx = nil
                 0.step(to: str.size, by: 2) do |i|
                   binidx = i if str[i, 2] == binary_terminator
                 end
                 s = if binidx.nil?
                       str
                     else
                       str[0, binidx]
                     end
                 s.force_encoding(self_encoding)
               else
                 str.encode(self_encoding)
               end
        str2 = str2[0, @static_length / 2] if @static_length.is_a? Integer
        idx = str2.index(+"\x00".encode(self_encoding))
        str2 = str2[0, idx] unless idx.nil?
        self.replace str2
        self
      end

      private

      def self_encoding
        @unicode ? Encoding::UTF_16LE : Encoding:: ASCII_8BIT
      end

      def binary_terminator
        @unicode ? "\x00\x00" : "\x00"
      end
    end
  end
end
