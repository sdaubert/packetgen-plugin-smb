# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB
    module Negotiate
      # A SMB_Dialect struct containing:
      # * a 8-bit {#format} field, which should be set to 0x02,
      # * a null-terminated string identifying a SMB dialect.
      # @author Sylvain Daubert
      class Dialect < BinStruct::Struct
        # @!attribute format
        #  8-bit format. Should be +2+ to indicate a null-terminated string for
        #  {#dialect} field.
        #  @return [Integer]
        define_attr :format, BinStruct::Int8, default: 2
        # @!attribute dialect
        #  Null-terminated string identifying a SMB dialect.
        #  @return [String]
        define_attr :dialect, BinStruct::CString

        # @return [String]
        def to_human
          self[:dialect].to_human
        end
      end

      # Specialized {BinStruct::Array} to embed {Dialect Dialects}.
      # @author Sylvain Daubert
      class ArrayOfDialect < BinStruct::Array
        set_of Dialect
      end
    end
  end
end
