# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB
    class Browser
      # Host announcement browser frame.
      #
      # Such a frame is used by a server to advertise its presence and
      # specify the types of resources and services it supports.
      # @author Sylvain Daubert
      class HostAnnouncement < Browser
        # @return [String]
        def self.protocol_name
          return @protocol_name if @protocol_name

          basename = to_s.sub(/^.*::/, '')
          @protocol_name = "SMB::Browser::#{basename}"
        end

        remove_attr :body
        update_attr :opcode, default: 1
        # @!attribute update_count
        #  8-bit integer. Not used. Should be 0
        #  @return [Integer]
        define_attr :update_count, BinStruct::Int8, default: 0
        # @!attribute periodicity
        #  32-bit integer that must be the announcement frequency of the
        #  server in milliseconds.
        # @return [Integer]
        define_attr :periodicity, BinStruct::Int32le
        # @!attribute server_name
        #  Null-terminated ASCII string of 16-byte length. Used to identify
        #  server.
        #  @return [String]
        define_attr :server_name, BinStruct::CString, static_length: 16
        # @!attribute os_ver_maj
        #  8-bit integer indicating the OS major version number
        #  @return [Integer]
        define_attr :os_ver_maj, BinStruct::Int8
        # @!attribute os_ver_min
        #  8-bit integer indicating the OS minor version number
        #  @return [Integer]
        define_attr :os_ver_min, BinStruct::Int8
        # @!attribute server_type
        #  32-bit integer indicating the type of the server
        #  @return [Integer]
        define_attr :server_type, BinStruct::Int32le
        # @!attribute browser_ver_maj
        #  8-bit Browser protocol major version number. Should be 15.
        #  @return [Integer]
        define_attr :browser_ver_maj, BinStruct::Int8, default: 15
        # @!attribute browser_ver_min
        #  8-bit Browser protocol minor version number. Should be 1.
        #  @return [Integer]
        define_attr :browser_ver_min, BinStruct::Int8, default: 1
        # @!attribute signature
        #  16-bit sinature integer. Should be 0xAA55.
        #  @return [Integer]
        define_attr :signature, BinStruct::Int16le, default: 0xaa55
        # @!attribute comment
        #  Null-terminated ASCII string.
        #  @return [String]
        define_attr :comment, BinStruct::CString
      end
      PacketGen::Header.add_class HostAnnouncement
      SMB::Trans::Request.bind HostAnnouncement, name: '\\MAILSLOT\\BROWSE', body: ->(v) { v[0] == OPCODES['HostAnnouncement'] }
    end
  end
end
