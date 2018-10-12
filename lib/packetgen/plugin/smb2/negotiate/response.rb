# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB2
    module Negotiate
      # SMB2 Negotiate response structure
      #    0                   1                   2                   3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |        StructureSize          |         SecurityMode          |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |       DialectRevision         |        ContextCount           |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                          ServerGUID                           |
      #   +                                                               +
      #   |                                                               |
      #   +                                                               +
      #   |                                                               |
      #   +                                                               +
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                         Capabilities                          |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                          MaxTranSize                          |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                          MaxReadSize                          |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                         MaxWriteSize                          |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                          SystemTime                           |
      #   +                                                               +
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                          StartTime                            |
      #   +                                                               +
      #   |                                                               |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |        BufferOffset           |           BufferLength        |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                         ContextOffset                         |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |                        Buffer (variable)                      |
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
      class Response < Base
        # @!attribute structure_size
        #  16-bit negotiate request structure size. Should be 65.
        #  @return [Integer]
        define_field :structure_size, PacketGen::Types::Int16le, default: 65
        # @!attribute security_mode
        #  16-bit security mode field.
        #  @return [Integer]
        define_field :security_mode, PacketGen::Types::Int16leEnum, enum: Negotiate::Request::SECURITY_MODES
        # @!attribute dialect
        #  16-bit prefered SMB2 protocol dialect number.
        #  @return [Integer]
        define_field :dialect, PacketGen::Types::Int16le
        # @!attribute context_count
        #  Only for SMB3 dialect.
        #  @return [Integer]
        define_field :context_count, PacketGen::Types::Int16le
        # @!attribute server_guid
        #  @return []
        define_field :server_guid, GUID
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
        # @!attribute max_trans_size
        #  32-bit value indicating the maximum size of the buffer used for
        #  QUERY_INFO, QUERY_DIRECTORY, SET_INFO and CHANGE_NOTIFY operations.
        #  @return [Integer]
        define_field :max_trans_size, PacketGen::Types::Int32le
        # @!attribute max_read_size
        #  32-bit value indicating the maximum size of a READ request
        #  @return [Integer]
        define_field :max_read_size, PacketGen::Types::Int32le
        # @!attribute max_write_size
        #  32-bit value indicating the maximum size of a WRITE request
        #  @return [Integer]
        define_field :max_write_size, PacketGen::Types::Int32le
        # @!attribute system_time
        #  System time of the SMB2 server
        #  @return [SMB::Filetime]
        define_field :system_time, SMB::Filetime
        # @!attribute start_time
        #  Start time of the SMB2 server
        #  @return [SMB::Filetime]
        define_field :start_time, SMB::Filetime
        # @!attribute buffer_offset
        #  The offset, from the beginning of the SMB2 header of the {#buffer}.
        #  @return [Integer]
        define_field :buffer_offset, PacketGen::Types::Int16le
        # @!attribute buffer_length
        #  The length of the {#buffer} field.
        #  @return [Integer]
        define_field :buffer_length, PacketGen::Types::Int16le
        # @!attribute context_offset
        #  Only for SMB3 dialect.
        #  @return [Integer]
        define_field :context_offset, PacketGen::Types::Int32le
        # @!attribute buffer
        #  @return [String]
        define_field :buffer, GSSAPI
        # @!attribute pad
        #  Optional padding between the end of the {#buffer} field and the first negotiate
        #  context in {#context_list} so that the first negotiate context is 8-byte aligned.
        #  @return [String]
        define_smb2_pad_field :pad
        # @!attribute context_list
        #  If {#dialect} has the value 0x0311, then this field must contain an array
        #  of {Context}
        #  @return [ArrayOfContext]
        define_field :context_list, ArrayOfContext, builder: ->(h, t) { t.new(counter: h[:context_count]) }

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
            else
              str << PacketGen::Inspect.inspect_attribute(attr, self[attr], 1)
            end
          end
          str
        end

        # Calculate and set {#context_offset}, {#buffer_offset} and {#buffer_length} fields.
        # Also calculate lengths in {Context contexts}.
        # @return [void]
        def calc_length
          self.context_offset = SMB2.new.sz + offset_of(:context_list)
          self.buffer_offset = SMB2.new.sz + offset_of(:buffer)
          self.buffer_length = buffer.sz
          context_list.each { |ctx| ctx.calc_length if ctx.respond_to? :calc_length }
        end

        # Protocol name
        # @return [String]
        def protocol_name
          'SMB2::Negotiate::Response'
        end
      end
    end
  end
end
