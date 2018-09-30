# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB
    class Browser
      # Local master announcement browser frame.
      #
      # Such a frame is used by a local master of a machine group to
      # advertise its presence.
      # @author Sylvain Daubert
      class LocalMasterAnnouncement < HostAnnouncement
        update_field :opcode, default: 15

        # @return [String]
        def protocol_name
          'SMB::Browser::LocalMasterAnnouncement'
        end
      end
      PacketGen::Header.add_class LocalMasterAnnouncement
      SMB::TransRequest.bind LocalMasterAnnouncement, name: '\\MAILSLOT\\BROWSE', body: ->(v) { v[0] == OPCODES['LocalMasterAnnouncement'] }
    end
  end
end
