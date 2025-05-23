# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB
    class Browser
      # Local master announcement browser frame.
      #
      # Such a frame is used by a local master of a machine group to
      # advertise its presence.
      # @author Sylvain Daubert
      class LocalMasterAnnouncement < HostAnnouncement
        update_attr :opcode, default: 15
      end
      PacketGen::Header.add_class LocalMasterAnnouncement
      SMB::Trans::Request.bind LocalMasterAnnouncement, name: '\\MAILSLOT\\BROWSE', body: ->(v) { v[0] == OPCODES['LocalMasterAnnouncement'] }
    end
  end
end
