# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB
    # Namespace for NT_CREATE_ANDX related classes
    module NtCreateAndX
      # SMB Command NtCreateAndX request.
      #
      # A NtCreateAndXRequest contains:
      # * a {#word_count} field (+Int8+), size, in 2-byte words of SMB
      #   parameters:
      #   * {#and_xcommand} (+Int8+), next command in packet,
      #   * {#rsv1} (+Int8+),
      #   * {#and_xoffset} (+Int16le+), offset of the next command from the
      #     start of SMB header,
      #   * {#rsv2} (+Int8+),
      #   * {#filename_len} (+Int16le+), size of {#filename} in SMB data,
      #   * {#flags} (+Int32le+),
      #   * {#root_dir_fid} (+Int32le+),
      #   * {#access_mask} (+Int32le+),
      #   * {#alloc_size} (+Int64le+),
      #   * {#fattributes} (+Int32le+),
      #   * {#share_access} (+Int32le+),
      #   * {#disposition} (+Int32le+),
      #   * {#options} (+Int32le+),
      #   * {#impersonation} (+Int32le+),
      #   * {#sec_flags} (+Int38+),
      # * #{byte_count} (+Int16le+), size in bytes of SMB data:
      #   * {#pad1} (+Int8),
      #   * {#filename} ({SMB::String}),
      #   * {#extra_bytes} (+String+).
      #
      # == Known limitations
      # 1. Only the first command is properly handled. Chained commands are not.
      # 2. {#filename} is mandatory handled as Windows Unicode string.
      # @author Sylvain Daubert
      class Request < PacketGen::Header::Base
        # Commands that may follow this one in a SMB packet
        COMMANDS = {
          'read' => 0x0a,
          'read_andx' => 0x2e,
          'ioctl' => 0x27,
          'no further commands' => 0xff
        }.freeze

        # @!attribute word_count
        #  The size, in 2-byte words, of the SMB parameters.
        #  @return [Integer]
        define_attr :word_count, BinStruct::Int8, default: 24
        # @!attribute and_xcommand
        #  8-bit command code for the next SMB command in the
        #  packet.
        #  @return [Integer]
        define_attr :and_xcommand, BinStruct::Int8Enum, enum: COMMANDS
        # @!attribute rsv1
        #  8-bit reserved field.
        #  @return [Integer]
        define_attr :rsv1, BinStruct::Int8, default: 0
        # @!attribute and_xoffset
        #  16-bit offset from the start of SMB header to the start of
        #  the  {#word_count} field in the next SMB command in this
        #  packet.
        #  @return [Integer]
        define_attr :and_xoffset, BinStruct::Int16le, default: 0
        # @!attribute rsv2
        #  8-bit reserved field.
        #  @return [Integer]
        define_attr :rsv2, BinStruct::Int8, default: 0
        # @!attribute filename_len
        #  16-bit length of the {#filename} field.
        #  @return [Integer]
        define_attr :filename_len, BinStruct::Int16le
        alias filename_length filename_len
        alias filename_length= filename_len=
        # @!attribute flags
        #  32-bit flags word
        #  @return [Integer]
        define_attr :flags, BinStruct::Int32le
        # @!attribute root_dir_fid
        #  32-bit file ID of an opened root directory.
        #  @return [Integer]
        define_attr :root_dir_fid, BinStruct::Int32le
        # @!attribute access_mask
        #  32-bit flags that indicate access rights.
        #  @return [Integer]
        define_attr :access_mask, BinStruct::Int32le
        # @!attribute alloc_size
        #  64-bit initial allocation size.
        #  @return [Integer]
        define_attr :alloc_size, BinStruct::Int64le
        # @!attribute fattributes
        #  32-bit extended file attributes.
        #  @return [Integer]
        define_attr :fattributes, BinStruct::Int32le
        # @!attribute share_access
        #  32-bit field that specifies how the file should be shared.
        #  @return [Integer]
        define_attr :share_access, BinStruct::Int32le
        # @!attribute disposition
        #  32-bit value that represents the action to take if the file
        #  already exists or if the file is a new file and does not already
        #  exist.
        #  @return [Integer]
        define_attr :disposition, BinStruct::Int32le
        # @!attribute options
        #  32-bit field containing flag options to use if creating the file
        #  or the directory.
        #  @return [Integer]
        define_attr :options, BinStruct::Int32le
        # @!attribute impersonation
        #  32-bit field specifying the impersonation level requested by
        #  the application.
        #  @return [Integer]
        define_attr :impersonation, BinStruct::Int32le
        # @!attribute sec_flags
        #  8-bit security flags.
        define_attr :sec_flags, BinStruct::Int8
        # @!attribute byte_count
        #  The size, in bytes, of the SMB data.
        #  @return [Integer]
        define_attr :byte_count, BinStruct::Int16le
        # @!attribute pad1
        #  Padding before {#filename} to align it on 16-bit boundary. Only present
        #  if {SMB#flags2_unicode?} is +true+.
        #  @return [Integer]
        define_attr :pad1, BinStruct::Int8, optional: ->(h) { h&.packet&.smb&.flags2_unicode? } # rubocop:disable Style/SafeNavigationChainLength
        # @!attribute filename
        #  A string that represents the fully qualified name of the file
        #  relative to the supplied TID
        # @return [String]
        define_attr :filename, SMB::String, builder: ->(h, t) { t.new(unicode: !h.packet || h.packet.smb.flags2_unicode?) }
        # @!attribute extra_bytes
        #  @return [Integer]
        define_attr :extra_bytes, BinStruct::String,
                    builder: ->(h, t) { t.new(length_from: -> { h.byte_count - (h.present?(:pad1) ? 1 : 0) - h[:filename].sz }) }

        # Give protocol name for this class
        # @return [String]
        def self.protocol_name
          'SMB::NtCreateAndX::Request'
        end

        # Compute {#filename_len} and {#byte_count}
        # @return [void]
        def calc_length
          self.filename_len = self[:filename].sz
          pad1sz = self.present?(:pad1) ? 1 : 0
          bcount = pad1sz + filename_len + self[:extra_bytes].sz
          self.byte_count = bcount
        end
      end
    end
  end
end
