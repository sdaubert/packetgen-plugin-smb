# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  # Module to group all NetBIOS headers
  # @author Sylvain Daubert
  module NetBIOS
  end
end

require_relative 'netbios/name'
require_relative 'netbios/session'
require_relative 'netbios/datagram'
