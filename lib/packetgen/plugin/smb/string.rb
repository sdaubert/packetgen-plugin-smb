# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB
    # SMB strings (UTF-16 little-endian or OEM).
    # @author Sylvain Daubert
    class String < PacketGen::Types::CString
      # @param [Boolean] value
      # @return [Boolean]
      attr_writer :unicode
      # @param [Boolean] null_terminated
      # @return [Boolean]
      attr_writer :null_terminated

      # @param [Hash] options
      # @option options [Integer] :static_length set a static length for this string
      # @option options [Boolean] :unicode If +true+, string is encoded as a UTF-16
      #    unicode string. If +false+, string is encode in ASCII. Defaults to +true+.
      # @option options [Boolean] :null_terminated If +true+, string is null-terminated.
      #    If +false+, string is not null-terminated. Defaults to +true+.
      def initialize(options={})
        super
        @unicode = options.key?(:unicode) ? options[:unicode] : true
        @null_terminated = options.key?(:null_terminated) ? options[:null_terminated] : true
        encoding = unicode? ? 'UTF-16LE' : 'ASCII-8BIT'
        self.encode!(encoding)
      end

      # @return [Boolean]
      def unicode?
        @unicode
      end

      # @return [Boolean]
      def null_terminated?
        @null_terminated
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

      # @return [String]
      def to_s
        s = super
        s.encode(self_encoding)
        return s if null_terminated?

        s[0...-binary_terminator.size]
      end

      # @return [String]
      def to_human
        super.encode('UTF-8')
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
