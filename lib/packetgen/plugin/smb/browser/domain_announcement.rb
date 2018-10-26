# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB
    class Browser
      # Local master announcement browser frame.
      #
      # Such a frame is used by a local master of a machine group to
      # announce the machine group it serves.
      # @author Sylvain Daubert
      class DomainAnnouncement < HostAnnouncement
        update_field :opcode, default: 12

        alias browser_conf_ver_maj os_ver_maj
        alias browser_conf_ver_min os_ver_min
        alias machine_group server_name
        alias local_master_name comment
      end
      PacketGen::Header.add_class DomainAnnouncement
      SMB::Trans::Request.bind DomainAnnouncement, name: '\\MAILSLOT\\BROWSE', body: ->(v) { v[0] == OPCODES['DomainAnnouncement'] }
    end
  end
end
