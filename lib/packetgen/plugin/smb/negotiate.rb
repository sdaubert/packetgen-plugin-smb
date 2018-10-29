# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB
    # Namespace for NEGOTIATE related classes
    # @author Sylvain Daubert
    module Negotiate; end
  end
end

require_relative 'negotiate/dialect'
require_relative 'negotiate/request'
require_relative 'negotiate/response'

PacketGen::Plugin::SMB.bind_command 'negotiate'
