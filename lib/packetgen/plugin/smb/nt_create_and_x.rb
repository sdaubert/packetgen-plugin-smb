# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB
    # SMB Command NtCreateAndX request.

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
    #   * {#attributes} (+Int32le+),
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
    # @since 0.1.0
    class NtCreateAndXRequest < PacketGen::Header::Base
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
      define_field :word_count, PacketGen::Types::Int8, default: 24
      # @!attribute and_xcommand
      #  8-bit command code for the next SMB command in the
      #  packet.
      #  @return [Integer]
      define_field :and_xcommand, PacketGen::Types::Int8Enum, enum: COMMANDS
      # @!attribute rsv1
      #  8-bit reserved field.
      #  @return [Integer]
      define_field :rsv1, PacketGen::Types::Int8, default: 0
      # @!attribute and_xoffset
      #  16-bit offset from the start of SMB header to the start of
      #  the  {#word_count} field in the next SMB command in this
      #  packet.
      #  @return [Integer]
      define_field :and_xoffset, PacketGen::Types::Int16le, default: 0
      # @!attribute rsv2
      #  8-bit reserved field.
      #  @return [Integer]
      define_field :rsv2, PacketGen::Types::Int8, default: 0
      # @!attribute filename_len
      #  16-bit length of the {#filename} field.
      #  @return [Integer]
      define_field :filename_len, PacketGen::Types::Int16le
      alias filename_length filename_len
      alias filename_length= filename_len=
      # @!attribute flags
      #  32-bit flags word
      #  @return [Integer]
      define_field :flags, PacketGen::Types::Int32le
      # @!attribute root_dir_fid
      #  32-bit file ID of an opened root directory.
      #  @return [Integer]
      define_field :root_dir_fid, PacketGen::Types::Int32le
      # @!attribute access_mask
      #  32-bit flags that indicate access rights.
      #  @return [Integer]
      define_field :access_mask, PacketGen::Types::Int32le
      # @!attribute alloc_size
      #  64-bit initial allocation size.
      #  @return [Integer]
      define_field :alloc_size, PacketGen::Types::Int64le
      # @!attribute attributes
      #  32-bit extended file attributes.
      #  @return [Integer]
      define_field :attributes, PacketGen::Types::Int32le
      # @!attribute share_access
      #  32-bit field that specifies how the file should be shared.
      #  @return [Integer]
      define_field :share_access, PacketGen::Types::Int32le
      # @!attribute disposition
      #  32-bit value that represents the action to take if the file
      #  already exists or if the file is a new file and does not already
      #  exist.
      #  @return [Integer]
      define_field :disposition, PacketGen::Types::Int32le
      # @!attribute options
      #  32-bit field containing flag options to use if creating the file
      #  or the directory.
      #  @return [Integer]
      define_field :options, PacketGen::Types::Int32le
      # @!attribute impersonation
      #  32-bit field specifying the impersonation level requested by
      #  the application.
      #  @return [Integer]
      define_field :impersonation, PacketGen::Types::Int32le
      # @!attribute sec_flags
      #  8-bit security flags.
      define_field :sec_flags, PacketGen::Types::Int8
      # @!attribute byte_count
      #  The size, in bytes, of the SMB data.
      #  @return [Integer]
      define_field :byte_count, PacketGen::Types::Int16le
      # @!attribute pad1
      #  Padding before {#filename} to align it on 16-bit boundary
      #  @return [Integer]
      define_field :pad1, PacketGen::Types::Int8
      # @!attribute filename
      #  A string that represents the fully qualified name of the file
      #  relative to the supplied TID
      # @return [String]
      define_field :filename, SMB::String
      # @!attribute extra_bytes
      #  @return [Integer]
      define_field :extra_bytes, PacketGen::Types::String,
                   builder: ->(h, t) { t.new(length_from: -> { h.byte_count - 1 - h[:filename].sz }) }

      # Give protocol name for this class
      # @return [String]
      def protocol_name
        'SMB::NtCreateAndXRequest'
      end

      # Compute {#filename_len} and {#byte_count}
      # @return [void]
      def calc_length
        self.filename_len = self[:filename].sz
        bcount = 1 + filename_len + self[:extra_bytes].sz
        self.byte_count = bcount
      end
    end

    # SMB Command NtCreateAndX response
    # @author Sylvain Daubert
    # @since 0.1.0
    class NtCreateAndXResponse < PacketGen::Header::Base
      # OpLock levels
      OP_LOCK_LEVELS = {
        'none' => 0,
        'exclusive' => 1,
        'batch' => 2,
        'level II' => 3,
      }.freeze

      # @!attribute word_count
      #  The size, in 2-byte words, of the SMB parameters.
      #  @return [Integer]
      define_field :word_count, PacketGen::Types::Int8, default: 34
      # @!attribute and_xcommand
      #  8-bit command code for the next SMB command in the
      #  packet.
      #  @return [Integer]
      define_field :and_xcommand, PacketGen::Types::Int8Enum, enum: NtCreateAndXRequest::COMMANDS
      # @!attribute rsv1
      #  8-bit reserved field.
      #  @return [Integer]
      define_field :rsv1, PacketGen::Types::Int8, default: 0
      # @!attribute and_xoffset
      #  16-bit offset from the start of SMB header to the start of
      #  the  {#word_count} field in the next SMB command in this
      #  packet.
      #  @return [Integer]
      define_field :and_xoffset, PacketGen::Types::Int16le, default: 0
      # @!attribute oplock_level
      #  8-bit OpLock level.
      #  @return [Integer]
      define_field :oplock_level, PacketGen::Types::Int8Enum, enum: OP_LOCK_LEVELS
      # @!attribute fid
      #  16-bit FID.
      #  @return [Integer]
      define_field :fid, PacketGen::Types::Int16le
      # @!attribute disposition
      #  32-bit value that represents the action to take if the file
      #  already exists or if the file is a new file and does not already
      #  exist.
      #  @return [Integer]
      define_field :disposition, PacketGen::Types::Int32le
      # @!attribute create_time
      #  64-bit integer representing the time that the file was created.
      #  @return [Integer]
      define_field :create_time, SMB::Filetime
      # @!attribute access_time
      #  64-bit integer representing the time that the file was last accessed.
      #  @return [Integer]
      define_field :access_time, SMB::Filetime
      # @!attribute write_time
      #  64-bit integer representing the time that the file was last writen.
      #  @return [Integer]
      define_field :write_time, SMB::Filetime
      # @!attribute change_time
      #  64-bit integer representing the time that the file was last changed.
      #  @return [Integer]
      define_field :change_time, SMB::Filetime
      # @!attribute attributes
      #  32-bit extended file attributes.
      #  @return [Integer]
      define_field :attributes, PacketGen::Types::Int32le
      # @!attribute alloc_size
      #  64-bit integer representing the number of bytes allocated to the file.
      #  @return [Integer]
      define_field :alloc_size, PacketGen::Types::Int64le
      # @!attribute end_of_file
      #  64-bit integer representing the end of file offset.
      #  @return [Integer]
      define_field :end_of_file, PacketGen::Types::Int64le
      # @!attribute res_type
      #  16-bit file type.
      #  @return [Integer]
      define_field :res_type, PacketGen::Types::Int16le
      # @!attribute pipe_status
      #  16-bit field that shows the status of the named pipe (if opened resource
      #  is a named pipe).
      #  @return [Integer]
      define_field :pipe_status, PacketGen::Types::Int16le
      # @!attribute directory
      #  8-bit field indicating is the FID represents a directory.
      #  @return [Integer]
      define_field :directory, PacketGen::Types::Int8
      # @!attribute byte_count
      #  The size, in bytes, of the SMB data. Should be zero.
      #  @return [Integer]
      define_field :byte_count, PacketGen::Types::Int16le, default: 0

      # Give protocol name for this class
      # @return [String]
      def protocol_name
        'SMB::NtCreateAndXResponse'
      end

      # Say if FID is a directory
      # @return [Boolean]
      def directory?
        self.directory > 0
      end

      # @!method human_create_time
      #  @return [String]
      # @!method human_access_time
      #  @return [String]
      # @!method human_write_time
      #  @return [String]
      # @!method human_change_time
      #  @return [String]
      %i[create access write change].each do |type|
        class_eval "def human_#{type}_time; self[:#{type}_time].to_human; end"
      end
    end

    self.bind_command 'nt_create_and_x'
  end
end
