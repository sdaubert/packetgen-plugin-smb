# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

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
        }.freeze

        # @!attribute structure_size
        #  16-bit negotiate request structure size. Should be 36.
        #  @return [Integer]
        define_attr :structure_size, BinStruct::Int16le, default: 36
        # @!attribute dialect_count
        #  16-bit number of dialects that are contained in {#dialects}.
        #  @return [Integer]
        define_attr :dialect_count, BinStruct::Int16le
        # @!attribute security_mode
        #  16-bit security mode field.
        #  @return [Integer]
        define_attr :security_mode, BinStruct::Int16leEnum, enum: SECURITY_MODES
        # @!attribute reserved
        #  16-bit reserved field.
        #  @return [Integer]
        define_attr :reserved, BinStruct::Int16le
        # @!attribute capabilities
        #  32-bit capabilities field.
        #  @return [Integer]
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
        define_bit_attr :capabilities, endian: :little,
                                       cap_rsv: 25, cap_encryption: 1, cap_dir_leasing: 1,
                                       cap_persistent_handles: 1, cap_multi_channel: 1,
                                       cap_large_mtu: 1, cap_leasing: 1, cap_dfs: 1
        # @!attribute client_guid
        #  @return []
        define_attr :client_guid, GUID
        # @!attribute context_offset
        #  Only for SMB3 dialect.
        #  @return [Integer]
        define_attr :context_offset, BinStruct::Int32le
        # @!attribute context_count
        #  Only for SMB3 dialect.
        #  @return [Integer]
        define_attr :context_count, BinStruct::Int16le
        # @!attribute reserved2
        #  Only for SMB3 dialect.
        #  @return [Integer]
        define_attr :reserved2, BinStruct::Int16le
        # @!attribute dialects
        #  Array of 16-bit integers specifying the supported dialtec revisions.
        #  @return [Array<BinStruct::Int16le>]
        define_attr :dialects, BinStruct::ArrayOfInt16le, builder: ->(h, t) { t.new(counter: h[:dialect_count]) }
        # @!attribute pad
        #  Optional padding between the end of the {#dialects} array and the first negotiate
        #  context in {#context_list} so that the first negotiate context is 8-byte aligned.
        #  @return [String]
        define_smb2_pad_field :pad
        # @!attribute context_list
        #  If {#dialects} contains the value 0x0311, then this field must contain an array
        #  of {Context}
        #  @return [ArrayOfContext]
        define_attr :context_list, ArrayOfContext, builder: ->(h, t) { t.new(counter: h[:context_count]) }

        # Protocol name
        # @return [String]
        def self.protocol_name
          'SMB2::Negotiate::Request'
        end

        # @return [String]
        def inspect # rubocop:disable Metrics/AbcSize
          super do |attr|
            case attr
            when :capabilities
              value = bits_on(attr).select { |b| respond_to?("#{b}?") && send("#{b}?") }
                                   .map { |v| v.to_s.delete_prefix('cap_') }
                                   .join(',')
              value = '%-16s (0x%08x)' % [value, self[attr].to_i]
              inspect_attr(attr, value)
            when :dialects
              list = self.dialects.map { |v| '%#x' % v.to_i }.join(',')
              inspect_attr(attr, list)
            end
          end
        end

        # Calculate and set {#context_offset} and {#pad} fields.
        # Also calculate lengths in {Context contexts}.
        # @return [Integer]
        def calc_length
          self[:pad].read SMB2::MAX_PADDING

          self.context_offset = 0
          self.context_offset = SMB2::HEADER_SIZE + offset_of(:context_list) unless context_list.empty?
          context_list.each { |ctx| ctx.calc_length if ctx.respond_to? :calc_length }
        end

        private

        def inspect_attr(attr, value)
          str = PacketGen::Inspect.shift_level
          str << (PacketGen::Inspect::FMT_ATTR % [self[attr].class.to_s.sub(/.*::/, ''), attr, value])
        end
      end
    end
  end
end
