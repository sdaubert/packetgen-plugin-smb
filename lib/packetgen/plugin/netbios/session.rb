# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  # Module to group all NetBIOS headers
  # @author Sylvain Daubert
  module NetBIOS
    # NetBIOS Session Service messages.
    # @author Sylvain Daubert
    class Session < PacketGen::Header::Base
      # Give protocol name
      # @return [String]
      def self.protocol_name
        'NetBIOS::Session'
      end

      # Port number for NetBIOS Session Service over TCP
      TCP_PORT = 139
      # Port number for NetBIOS Session Service over TCP (mainly used yb {SMB2})
      TCP_PORT2 = 445

      # Session packet types
      TYPES = {
        'message' => 0,
        'request' => 0x81,
        'positive_response' => 0x82,
        'negative_response' => 0x83,
        'retarget_response' => 0x84,
        'keep_alive' => 0x85,
      }.freeze

      # @!attribute type
      #  8-bit session packet type
      #  @return [Integer]
      define_attr :type, BinStruct::Int8Enum, enum: TYPES
      # @!attribute length
      #  17-bit session packet length
      #  @return [Integer]
      define_attr :length, BinStruct::Int24
      # @!attribute body
      #  @return [String]
      define_attr :body, BinStruct::String

      # Compute and set {#length} field
      # @return [Integer] calculated length
      def calc_length
        PacketGen::Header::Base.calculate_and_set_length(self, header_in_size: false)
      end

      # @api private
      # @note This method is used internally by PacketGen and should not be
      #       directly called
      # @since 2.7.0 Set TCP sport according to bindings, only if sport is 0.
      #  Needed by new bind API.
      def added_to_packet(packet)
        return unless packet.is? 'TCP'
        return unless packet.tcp.sport.zero?

        packet.tcp.sport = TCP_PORT
      end
    end
    PacketGen::Header.add_class Session
    PacketGen::Header::TCP.bind Session, dport: Session::TCP_PORT
    PacketGen::Header::TCP.bind Session, sport: Session::TCP_PORT
    PacketGen::Header::TCP.bind Session, dport: Session::TCP_PORT2
    PacketGen::Header::TCP.bind Session, sport: Session::TCP_PORT2
  end
end
