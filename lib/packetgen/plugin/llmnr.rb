# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  # Link-Local Multicast Name Resolution (LLMNR) header ({https://tools.ietf.org/html/rfc4795 RFC 4795}).
  # @author Sylvain Daubert
  class LLMNR < PacketGen::Header::DNS
    # UDP port number
    UDP_PORT = 5355
    # MAC address used with IPv4 multicast addresses
    MAC_IPV4_MCAST = '01:00:5e:00:00:fc'

    # @api private
    # @note This method is used internally by PacketGen and should not be
    #       directly called
    def added_to_packet(packet)
      packet.instance_eval <<-END_OF_DEFINITION
      def llmnrize(**kwargs)
        llmnr = headers.find { |hdr| hdr.is_a? PacketGen::Plugin::LLMNR }
        llmnr.llmnrize(**kwargs)
      end
      END_OF_DEFINITION
    end

    # Fixup IP header according to RFC 4795:
    # * optionally set destination address,
    # * set TTL to 1 if destination is a mcast address,
    # * set MAC destination address to {MAC_IPV4_MCAST} if destination address is a mcast one.
    # This method may be called as:
    #    # first way
    #    pkt.llmnr.llmnrize
    #    # second way
    #    pkt.llmnrize
    # @param [String,nil] dst destination address. May be a dotted IP
    #   address (by example '224.0.0.252').
    # @return [void]
    def llmnrize(dst: nil)
      ip = ip_header(self)
      ip.dst = dst unless dst.nil?
      ip.ttl = 1 if ip[:dst].mcast?

      # rubocop:disable Lint/HandleExceptions
      begin
        llh = ll_header(self)
        llh.dst = MAC_IPV4_MCAST if ip[:dst].mcast?
      rescue PacketGen::FormatError
      end
      # rubocop:enable Lint/HandleExceptions
    end
  end
  PacketGen::Header.add_class LLMNR
  PacketGen::Header::UDP.bind LLMNR, sport: LLMNR::UDP_PORT
  PacketGen::Header::UDP.bind LLMNR, dport: LLMNR::UDP_PORT
end
