# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

require_relative 'guid'

module PacketGen::Plugin
  class SMB2
    # Namespace for SESSION SETUP related classes
    # @author Sylvain Daubert
    module SessionSetup; end
  end
end

require_relative 'session_setup/request'
require_relative 'session_setup/response'

PacketGen::Plugin::SMB2.bind_command 'session_setup'
