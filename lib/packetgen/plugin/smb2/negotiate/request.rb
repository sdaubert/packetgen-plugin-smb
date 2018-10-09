# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB2
    module Negotiate
      # SMB2 Negotiate request structure
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |        StructureSize          |          DialectCount         |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |         SecurityMode          |            Reserved           |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                         Capabilities                          |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                          ClientGUID                           |
      #   +                                                               +
      #   |                                                               |
      #   +                                                               +
      #   |                                                               |
      #   +                                                               +
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                         ContextOffset                         |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |        ContextCount           |            Reserved2          |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                       Dialects (variable)                     |
      #   +                                                               +
      #   |                              ...                              |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                         Pad (variable)                        |
      #   +                                                               +
      #   |                              ...                              |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                     ContextList (variable)                    |
      #   +                                                               +
      #   |                              ...                              |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      # @author Sylvain Daubert
      class Request < Base
        # Security modes
        SECURITY_MODES = {
          'signing_enabled' => 1,
          'signing required' => 2
        }

        # @!attribute structure_size
        #  16-bit negotiate request structure size. Should be 36.
        #  @return [Integer]
        define_field :structure_size, PacketGen::Types::Int16le, default: 36
        # @!attribute dialect_count
        #  16-bit number of dialects that are contained in {#dialects}.
        #  @return [Integer]
        define_field :dialect_count, PacketGen::Types::Int16le
        # @!attribute security_mode
        #  16-bit security mode field.
        #  @return [Integer]
        define_field :security_mode, PacketGen::Types::Int16leEnum, enum: SECURITY_MODES
        # @!attribute reserved
        #  16-bit reserved field.
        #  @return [Integer]
        define_field :reserved, PacketGen::Types::Int16le
        # @!attribute capabilities
        #  32-bit capabilities field.
        #  @return [Integer]
        define_field :capabilities, PacketGen::Types::Int32le
        # @!attribute cap_encryption
        #  Indicates if encryption is supported
        #  @return [Boolean]
        # @!attribute cap_dir_leasing
        #  Indicates if directory leasing is supported
        #  @return [Boolean]
        # @!attribute cap_persistent_handles
        #  Indicates if persisten handles are supported
        #  @return [Boolean]
        # @!attribute cap_multi_channel
        #  Indicates if multiple channels are supported for a single session
        #  @return [Boolean]
        # @!attribute cap_large_mtu
        #  Indicates if multi credit operations are supported
        #  @return [Boolean]
        # @!attribute cap_leasing
        #  Indicates if leasing is supported
        #  @return [Boolean]
        # @!attribute cap_dfs
        #  Indicates if Distributed File system (DFS) is supported
        #  @return [Boolean]
        define_bit_fields_on :capabilities, :cap_rsv, 25, :cap_encryption, :cap_dir_leasing,
                                            :cap_persistent_handles, :cap_multi_channel,
                                            :cap_large_mtu, :cap_leasing, :cap_dfs
        # @!attribute client_guid
        #  @return []
        define_field :client_guid, GUID
        # @!attribute context_offset
        #  Only for SMB3 dialect.
        #  @return [Integer]
        define_field :context_offset, PacketGen::Types::Int32le
        # @!attribute context_count
        #  Only for SMB3 dialect.
        #  @return [Integer]
        define_field :context_count, PacketGen::Types::Int16le
        # @!attribute reserved2
        #  Only for SMB3 dialect.
        #  @return [Integer]
        define_field :reserved2, PacketGen::Types::Int16le
        # @!attribute dialects
        #  Array of 16-bit integers specifying the supported dialtec revisions.
        #  @return [Array<PacketGen::Types::Int16le>]
        define_field :dialects, PacketGen::Types::ArrayOfInt16le, builder: ->(h, t) { t.new(counter: h[:dialect_count]) }
        # @!attribute pad
        #  Optional padding between the end of the {#dialects} array and the first negotiate
        #  context in {#context_list} so that the first negotiate context is 8-byte aligned.
        #  @return [String]
        define_smb2_pad_field :pad
        # @!attribute context_list
        #  If {#dialects} contains he value 0x0311, then this field must contain an array
        #  of {NegotiateContext}
        #  @return [ArrayOfNegotiateContext]
        define_field :context_list, ArrayOfContext

        # @return [String]
        def inspect
          str = PacketGen::Inspect.dashed_line(self.class, 1)
          fields.each do |attr|
            case attr
            when :capabilities
              value = bits_on(attr).reject { |_, v| v > 1 }
                                   .keys
                                   .select { |b| send("#{b}?") }
                                   .map(&:to_s)
                                   .join(',')
                                   .gsub!(/cap_/, '')
              value = '%-16s (0x%08x)' % [value, self[attr].to_i]
              str << PacketGen::Inspect.shift_level(1)
              str << PacketGen::Inspect::FMT_ATTR % [self[attr].class.to_s.sub(/.*::/, ''),
                                                     attr, value]
            when :dialects
              list = self.dialects.map { |v| "%#04x" % v.to_i }.join(',')
              str << PacketGen::Inspect.shift_level(1)
              str << PacketGen::Inspect::FMT_ATTR % [self[attr].class.to_s.sub(/.*::/, ''),
                                                     attr, list]

            else
              str << PacketGen::Inspect.inspect_attribute(attr, self[attr], 1)
            end
          end
          str
        end

        # Protocol name
        # @return [String]
        def protocol_name
          'SMB2::Negotiate::Request'
        end
      end
    end
  end
end
