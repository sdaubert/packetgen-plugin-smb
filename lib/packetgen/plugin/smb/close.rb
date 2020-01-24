# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB
    # Namespace for CLOSE related classes
    module Close; end
  end
end

require_relative 'close/request'
require_relative 'close/response'

PacketGen::Plugin::SMB.bind_command 'close'
