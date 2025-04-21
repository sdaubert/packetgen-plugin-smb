# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class NTLM
    class Ntlmv2Response < BinStruct::Struct
      # @!attribute response
      #   16-byte array of unsigned char containing the client's NT challenge
      #   response.
      #   @return [String]
      define_attr :response, BinStruct::String, static_length: 16
      alias ntproof_str response
      alias ntproof_str= response=

      # @!attribute type
      #   8-bit current version of the challenge. Should be 1.
      #   @return [Integer]
      define_attr :type, BinStruct::Int8, default: 1
      # @!attribute hi_type
      #   8-bit maximum supported version of the challenge. Should be 1.
      #   @return [Integer]
      define_attr :hi_type, BinStruct::Int8, default: 1
      # @!attribute reserved1
      #   16-bit reserved word.
      #   @return [Integer]
      define_attr :reserved1, BinStruct::Int16le
      # @!attribute reserved2
      #   32-bit reserved word.
      #   @return [Integer]
      define_attr :reserved2, BinStruct::Int32le
      # @!attribute timestamp
      #   64-bit current system time.
      #   @return [SMB::Filetime]
      define_attr :timestamp, SMB::Filetime
      # @!attribute client_challenge
      #   8-byte challenge from client
      #   @return [String]
      define_attr :client_challenge, BinStruct::String, static_length: 8
      # @!attribute reserved3
      #   32-bit reserved word.
      #   @return [Integer]
      define_attr :reserved3, BinStruct::Int32le
      # @!attribute avpairs
      #   @return [ArrayOfAvPair]
      define_attr :avpairs, ArrayOfAvPair

      # @return [false]
      def empty?
        false
      end

      alias size sz
    end
  end
end
