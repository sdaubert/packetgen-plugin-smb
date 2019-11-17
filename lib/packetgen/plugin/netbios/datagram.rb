# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  # Module to group all NetBIOS headers
  # @author Sylvain Daubert
  module NetBIOS
    # NetBIOS Datagram Service messages.
    # @author Sylvain Daubert
    class Datagram < PacketGen::Header::Base
      # Give protocol name
      # @return [String]
      def self.protocol_name
        'NetBIOS::Datagram'
      end

      # Port number for NetBIOS Session Service over TCP
      UDP_PORT = 138

      # Datagram packet types
      TYPES = {
        'direct_unique' => 0x10,
        'direct_group' => 0x11,
        'broadcast' => 0x12,
        'error' => 0x13,
        'query_request' => 0x14,
        'positive_query_resp' => 0x15,
        'negative_query_resp' => 0x16,
      }.freeze

      # @!attribute type
      #  8-bit session packet type
      #  @return [Integer]
      define_field :type, PacketGen::Types::Int8Enum, enum: TYPES
      # @!attribute flags
      #  8-bit flags
      #  @return [Integer]
      define_field :flags, PacketGen::Types::Int8
      # @!attribute dgm_id
      #  16-bit next transaction ID for datagrams
      #  @return [Integer]
      define_field :dgm_id, PacketGen::Types::Int16
      # @!attribute src_ip
      #  Source IP address
      # @return [IP::Addr]
      define_field :src_ip, PacketGen::Header::IP::Addr
      # @!attribute src_port
      #  Source port
      # @return [IP::Addr]
      define_field :src_port, PacketGen::Types::Int16
      # @!attribute dgm_length
      #  Length of data + second level of encoded names. Not present in error datagram.
      # @return [Integer]
      define_field :dgm_length, PacketGen::Types::Int16, optional: ->(h) { h.type != 0x13 }
      # @!attribute packet_offset
      # Not present in error datagram.
      # @return [Integer]
      define_field :packet_offset, PacketGen::Types::Int16, optional: ->(h) { h.type != 0x13 }
      # @!attribute error_code
      #  Error code. Only present in error datagrams.
      #  @return [Integer]
      define_field :error_code, PacketGen::Types::Int16, optional: ->(h) { h.type == 0x13 }
      # @!attribute src_name
      #  NetBIOS source name. Only present in direct_unique, direct_group and broadcast datagrams.
      #  @return []
      define_field :src_name, Name, default: '', optional: ->(h) { (h.type >= 0x10) && (h.type <= 0x12) }
      # @!attribute dst_name
      #  NetBIOS destination name. Present in all but error datagrams.
      #  @return []
      define_field :dst_name, Name, default: '', optional: ->(h) { h.type != 0x13 }
      # @!attribute body
      #  User data. Ony present in direct_unique, direct_group and broadcast datagrams.
      #  @return [String]
      define_field :body, PacketGen::Types::String, optional: ->(h) { (h.type >= 0x10) && (h.type <= 0x12) }

      # @!attribute :rsv
      #  4-bit rsv field. 4 upper bits of {#flags}
      #  @return [Integer]
      # @!attribute :snt
      #  2-bit SNT (Source end-Node Type) field from {#flags}.
      #  @return [Integer]
      # @!attribute f
      #  First packet flag. If set then this is first
      #  (and possibly only) fragment of NetBIOS datagram.
      #  @return [Boolean]
      # @!attribute m
      #  More flag. If set then more NetBIOS datagram
      #  fragments follow.
      #  @return [Boolean]
      define_bit_fields_on :flags, :rsv, 4, :snt, 2, :f, :m

      # Compute and set {#dgm_length} field
      # @return [Integer] calculated length
      def calc_length
        length = self[:body].sz
        length += self[:src_name].sz if present?(:src_name)
        length += self[:dst_name].sz if present?(:dst_name)
        self.dgm_length = length
      end
    end
    PacketGen::Header.add_class Datagram
    PacketGen::Header::UDP.bind Datagram, dport: Datagram::UDP_PORT, sport: Datagram::UDP_PORT
  end
end
