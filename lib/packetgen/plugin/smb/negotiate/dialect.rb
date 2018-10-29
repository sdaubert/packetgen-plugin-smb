module PacketGen::Plugin
  class SMB
    module Negotiate
      # A SMB_Dialect struct containing:
      # * a 8-bit {#format} field, which should be set to 0x02,
      # * a null-terminated string identifying a SMB dialect.
      # @author Sylvain Daubert
      class Dialect < PacketGen::Types::Fields
        # @!attribute format
        #  8-bit format. Should be +2+ to indicate a null-terminated string for
        #  {#dialect} field.
        #  @return [Integer]
        define_field :format, PacketGen::Types::Int8, default: 2
        # @!attribute dialect
        #  Null-terminated string identifying a SMB dialect.
        #  @return [String]
        define_field :dialect,PacketGen::Types::CString
      end

      # Specialized {PacketGen::Types::Array} to embed {Dialect Dialects}.
      # @author Sylvain Daubert
      class ArrayOfDialect < PacketGen::Types::Array
        set_of Dialect
      end
    end
  end
end
