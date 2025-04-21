# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

require 'forwardable'

module PacketGen::Plugin
  class SMB
    # SMB strings (UTF-16 little-endian or OEM).
    # @author Sylvain Daubert
    class String
      extend Forwardable
      include BinStruct::Structable

      def_delegators :@string, :[], :length, :size, :inspect, :==, :<<,
                     :unpack, :force_encoding, :encoding, :index, :empty?,
                     :encode

      # @return [::String]
      attr_reader :string
      # @param [Boolean] null_terminated
      # @return [Boolean]
      attr_writer :null_terminated

      # @param [Hash] options
      # @option options [Boolean] :unicode If +true+, string is encoded as a UTF-16
      #    unicode string. If +false+, string is encode in ASCII. Defaults to +true+.
      # @option options [Boolean] :null_terminated If +true+, string is null-terminated.
      #    If +false+, string is not null-terminated. Defaults to +true+.
      def initialize(options={})
        @unicode = options.key?(:unicode) ? options[:unicode] : true
        @null_terminated = options.key?(:null_terminated) ? options[:null_terminated] : true
        @string = +''.encode(self_encoding)
      end

      # @return [Boolean]
      def unicode?
        @unicode
      end

      # @param [Boolean] bool
      # @return [Boolean]
      def unicode=(bool)
        @unicode = bool
        @string.force_encoding(self_encoding)
        bool
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
                 str.dup.force_encoding(self_encoding)
               else
                 str.encode(self_encoding)
               end
        idx = str2.index(+"\x00".encode(self_encoding))
        str2 = str2[0, idx] unless idx.nil?
        @string = str2
        self
      end

      # @return [String]
      def to_s
        str = string.dup.force_encoding('BINARY')
        return str unless null_terminated?

        str << binary_terminator.force_encoding('BINARY')
      end

      # Populate String from a human readable (ie UTF-8) string
      # @param [String] str
      # @return [self]
      def from_human(str)
        return self if str.nil?

        @string = str.encode(self_encoding)
        self
      end

      # @return [String]
      def to_human
        string.encode('UTF-8')
      end

      private

      def self_encoding
        @unicode ? Encoding::UTF_16LE : Encoding::ASCII_8BIT
      end

      def binary_terminator
        [0].pack('C').encode(self_encoding)
      end
    end
  end
end
