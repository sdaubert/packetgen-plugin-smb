# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class SMB
    # Namespace for NT_CREATE_ANDX related classes
    module NtCreateAndX
      # SMB Command NtCreateAndX response
      # @author Sylvain Daubert
      class Response < PacketGen::Header::Base
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
        define_attr :word_count, BinStruct::Int8, default: 34
        # @!attribute and_xcommand
        #  8-bit command code for the next SMB command in the
        #  packet.
        #  @return [Integer]
        define_attr :and_xcommand, BinStruct::Int8Enum, enum: Request::COMMANDS
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
        # @!attribute oplock_level
        #  8-bit OpLock level.
        #  @return [Integer]
        define_attr :oplock_level, BinStruct::Int8Enum, enum: OP_LOCK_LEVELS
        # @!attribute fid
        #  16-bit FID.
        #  @return [Integer]
        define_attr :fid, BinStruct::Int16le
        # @!attribute disposition
        #  32-bit value that represents the action to take if the file
        #  already exists or if the file is a new file and does not already
        #  exist.
        #  @return [Integer]
        define_attr :disposition, BinStruct::Int32le
        # @!attribute create_time
        #  64-bit integer representing the time that the file was created.
        #  @return [Integer]
        define_attr :create_time, SMB::Filetime
        # @!attribute access_time
        #  64-bit integer representing the time that the file was last accessed.
        #  @return [Integer]
        define_attr :access_time, SMB::Filetime
        # @!attribute write_time
        #  64-bit integer representing the time that the file was last writen.
        #  @return [Integer]
        define_attr :write_time, SMB::Filetime
        # @!attribute change_time
        #  64-bit integer representing the time that the file was last changed.
        #  @return [Integer]
        define_attr :change_time, SMB::Filetime
        # @!attribute fattributes
        #  32-bit extended file attributes.
        #  @return [Integer]
        define_attr :fattributes, BinStruct::Int32le
        # @!attribute alloc_size
        #  64-bit integer representing the number of bytes allocated to the file.
        #  @return [Integer]
        define_attr :alloc_size, BinStruct::Int64le
        # @!attribute end_of_file
        #  64-bit integer representing the end of file offset.
        #  @return [Integer]
        define_attr :end_of_file, BinStruct::Int64le
        # @!attribute res_type
        #  16-bit file type.
        #  @return [Integer]
        define_attr :res_type, BinStruct::Int16le
        # @!attribute pipe_status
        #  16-bit field that shows the status of the named pipe (if opened resource
        #  is a named pipe).
        #  @return [Integer]
        define_attr :pipe_status, BinStruct::Int16le
        # @!attribute directory
        #  8-bit field indicating is the FID represents a directory.
        #  @return [Integer]
        define_attr :directory, BinStruct::Int8
        # @!attribute byte_count
        #  The size, in bytes, of the SMB data. Should be zero.
        #  @return [Integer]
        define_attr :byte_count, BinStruct::Int16le, default: 0

        # Give protocol name for this class
        # @return [String]
        def self.protocol_name
          'SMB::NtCreateAndX::Response'
        end

        # Say if FID is a directory
        # @return [Boolean]
        def directory?
          self.directory.positive?
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
          class_eval "def human_#{type}_time; self[:#{type}_time].to_human; end" # def human_create_time; self[:create_time].to_human; end
        end
      end
    end
  end
end
