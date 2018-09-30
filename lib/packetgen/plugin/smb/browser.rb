# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB
    # Browser Trans sub-protocol.
    # See subclasses.
    # @author Sylvain Daubert
    class Browser < PacketGen::Header::Base
      # Give protocol name for this class
      # @return [String]
      def self.protocol_name
        'SMB::Browser'
      end

      OPCODES = {
        'HostAnnouncement' => 1,
        'HostAnnouncementReq' => 2,
        'RequestElection' => 8,
        'GetBackupListReq' => 9,
        'GetBackupListResp' => 10,
        'BecomeBackup' => 11,
        'DomainAnnouncement' => 12,
        'MasterAnnouncement' => 13,
        'ResetStateRequest' => 14,
        'LocalMasterAnnouncement' => 15
      }.freeze

      # @!attribute opcode
      #  8-bit opcode
      #  @return [Integer]
      define_field :opcode, PacketGen::Types::Int8Enum, enum: OPCODES
      # @!attribute body
      #  @return [String]
      define_field :body, PacketGen::Types::String

      alias old_read read
      private :old_read

      # Populate object from a binary string
      # @param [String] str
      # @return [Browser] may return a subclass object if a more specific class
      #   may be determined
      def read(str)
        if self.class == Browser
          return self if str.nil?

          PacketGen.force_binary str
          self[:opcode].read str[0]

          opcode_klass = Browser.const_get(self[:opcode].to_human) if Browser.const_defined?(self[:opcode].to_human)
          if opcode_klass
            opcode_klass.new.read str
          else
            private_read str
          end
        else
          private_read str
        end
      end

      # Callback called when a Browser header is added to a packet.
      # Here, add +#smb_browser+ method as a shortcut to existing
      # +#smb_browser_*+ method.
      # @param [Packet] packet
      # @return [void]
      def added_to_packet(packet)
        return if packet.respond_to? :smb_browser

        packet.instance_eval("def smb_browser(arg=nil); header(#{self.class}, arg); end")
      end

      private

      def private_read(str)
        old_read str
      end
    end
    PacketGen::Header.add_class Browser
    Trans::Request.bind Browser, name: '\\MAILSLOT\\BROWSE'
  end
end

require_relative 'browser/host_announcement'
require_relative 'browser/domain_announcement'
require_relative 'browser/local_master_announcement'
