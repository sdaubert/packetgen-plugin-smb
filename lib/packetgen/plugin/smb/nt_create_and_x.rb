# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB
    # Namespace for NT_CREATE_ANDX related classes
    module NtCreateAndX; end
  end
end

require_relative 'ntcreateandx/request'
require_relative 'ntcreateandx/response'

PacketGen::Plugin::SMB.bind_command 'nt_create_and_x'
