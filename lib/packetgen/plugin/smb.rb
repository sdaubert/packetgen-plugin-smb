# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  # Server Message Block (SMB) header.
  # @author Sylvain Daubert
  class SMB < PacketGen::Header::Base
    # Known commands
    COMMANDS = {
      'delete_dir' => 0x01,
      'close' => 0x04,
      'delete' => 0x06,
      'query_info2' => 0x23,
      'trans' => 0x25,
      'echo' => 0x2b,
      'open_and_x' => 0x2d,
      'read_and_x' => 0x2e,
      'write_and_x' => 0x2f,
      'trans2' => 0x32,
      'tree_disconnect' => 0x71,
      'negotiate' => 0x72,
      'session_setup_and_x' => 0x73,
      'tree_connect_and_x' => 0x75,
      'nt_trans' => 0xa0,
      'nt_create_and_x' => 0xa2
    }.freeze

    # SMB marker, on start of header
    MARKER = PacketGen.force_binary("\xffSMB")

    # @!attribute protocol
    #  This field must contain {MARKER SMB marker}
    #  @return [String]
    define_field :protocol, PacketGen::Types::String, static_length: 4, default: MARKER
    # @!attribute command
    #  8-bit SMB command
    #  @return [Integer]
    define_field :command, PacketGen::Types::Int8Enum, enum: COMMANDS
    # @!attribute status
    #  32-bit status field. Used to communicate errors from server to client.
    #  @return [Integer]
    define_field :status, PacketGen::Types::Int32le
    # @!attribute flags
    #  8-bit flags field
    #  @return [Integer]
    define_field :flags, PacketGen::Types::Int8
    # @!attribute flags2
    #  16-bit flags field
    #  @return [Integer]
    define_field :flags2, PacketGen::Types::Int16le
    # @!attribute pid_high
    #  16 high order bits of a process identifier (PID)
    #  @return [Integer]
    define_field :pid_high, PacketGen::Types::Int16le
    # @!attribute sec_features
    #  64-bit field. May be:
    #  * a 64-bit cryptographic message signature if signature was negotiated,
    #  * a SecurityFeatures structure, only over connectionless transport,
    #    composed of:
    #    * a 16-bit sequence number,
    #    * a 16-bit connection identifier (CID),
    #    * a 32-bit key to validate message,
    #  * a reserved field in all others cases.
    #  @return [Integer]
    define_field :sec_features, PacketGen::Types::Int64le
    # @!attribute reserved
    #  16-bit reserved field
    #  @return [Integer]
    define_field :reserved, PacketGen::Types::Int16le
    # @!attribute tid
    #  16-bit tree identifier (TID)
    define_field :tid, PacketGen::Types::Int16le
    # @!attribute pid
    #  16 low order bits of a process identifier (PID)
    #  @return [Integer]
    define_field :pid, PacketGen::Types::Int16le
    # @!attribute uid
    #  16-bit user identifier (UID)
    define_field :uid, PacketGen::Types::Int16le
    # @!attribute mid
    #  16-bit multiplex identifier (MID)
    define_field :mid, PacketGen::Types::Int16le
    # @!attribute body
    #  @return [String]
    define_field :body, PacketGen::Types::String
    # @!attribute flags_reply?
    #  When set, the message is a reply from server to client.
    #  @return [Boolean]
    # @!attribute flags_opbatch?
    #  Obsolescent.
    #  @return [Boolean]
    # @!attribute flags_oplock?
    #  Obsolescent.
    #  @return [Boolean]
    # @!attribute flags_canon_paths?
    #  Obsolescent.
    #  @return [Boolean]
    # @!attribute flags_case_insensitive?
    #  Obsolete.
    #  @return [Boolean]
    # @!attribute flags_reserved?
    #  @return [Boolean]
    # @!attribute flags_rbuf_avail?
    #  Obsolete.
    #  @return [Boolean]
    # @!attribute flags_locknread
    #  When set in SMB_COM_NEGOTIATE response, the server supports
    #  SMB_COM_LOCK_AND_READ and SNB_COM_WRITE_AND_UNLOCK commands.
    #  @return [Boolean]
    define_bit_fields_on :flags, :flags_reply, :flags_opbatch, :flags_oplock,
                         :flags_canon_paths, :flags_case_insensitive,
                         :flags_reserved, :flags_buf_avail, :flags_locknread
    # @!attribute flags2_unicode?
    #  If set, each field that contains a string in this message is encoded
    #  as UTF-16.
    #  @return [Boolean]
    # @!attribute flags2_ntstatus?
    #  If set in a client request, server must return errors as NTSTATUS, else
    #  as SMBSTATUS.
    #  @return [Boolean]
    # @!attribute flags2_paging_io?
    #  Client may read a file if it does not have read permission but have
    #  execute one.
    #  @return [Boolean]
    # @!attribute flags2_dfs?
    #  If set, any pathnames should be resolved in the Distributed File System
    #  (DFS).
    #  @return [Boolean]
    # @!attribute flags2_extended_security?
    #  @return [Boolean]
    # @!attribute flags2_reparse_path?
    #  @return [Boolean]
    # @!attribute flags2_reserved
    #  3-bit reserved field
    #  @return [Integer]
    # @!attribute flags2_is_long_name?
    #  @return [Boolean]
    # @!attribute flags2_rsv?
    #  @return [Boolean]
    # @!attribute flags2_security_signature_required?
    #  @return [Boolean]
    # @!attribute flags2_compressed?
    #  @return [Boolean]
    # @!attribute flags2_signature?
    #  @return [Boolean]
    # @!attribute flags2_eas?
    #  @return [Boolean]
    # @!attribute flags2_long_names?
    #  If unset, file names must adhere to the 8.3 naming convention.
    #  @return [Boolean]
    define_bit_fields_on :flags2, :flags2_unicode, :flags2_ntstatus,
                         :flags2_paging_io, :flags2_dfs, :flags2_extended_security,
                         :flags2_reparse_path, :flags2_reserved, 3,
                         :flags2_is_long_name, :flags2_rsv,
                         :flags2_security_signature_required, :flags2_compresses,
                         :flags2_signature, :flags2_eas, :flags2_long_names

    # Helper to bind a SMB command to {SMB} header.
    # @param [String] command name
    # @return [void]
    def self.bind_command(command)
      contantized = command.capitalize.gsub(/_(\w)/) { $1.upcase }
      krequest = self.const_get("#{contantized}::Request")
      kresponse = self.const_get("#{contantized}::Response")
      PacketGen::Header.add_class krequest
      self.bind krequest, command: SMB::COMMANDS[command], flags: ->(v) { v.nil? ? 0 : (v & 0x80).zero? }
      PacketGen::Header.add_class kresponse
      self.bind kresponse, command: SMB::COMMANDS[command], flags: ->(v) { v.nil? ? 0 : (v & 0x80 == 0x80) }
    end

    # Check if this is really a SMB2 header. Check {#protocol} has value {MARKER}.
    # @return [Boolean]
    def parse?
      protocol == MARKER
    end

    # @return [String]
    def inspect
      super do |attr|
        case attr
        when :flags, :flags2
          value = bits_on(attr).reject { |_, v| v > 1 }
                               .keys
                               .select { |b| send("#{b}?") }
                               .map(&:to_s)
                               .join(',')
                               .gsub!(/#{attr}_/, '')
          value = '%-16s (0x%02x)' % [value, self[attr].to_i]
          str = PacketGen::Inspect.shift_level
          str << (PacketGen::Inspect::FMT_ATTR % [self[attr].class.to_s.sub(/.*::/, ''), attr, value])
        end
      end
    end
  end
  PacketGen::Header.add_class SMB
  NetBIOS::Session.bind SMB, body: ->(val) { val.nil? ? SMB::MARKER : val[0..3] == SMB::MARKER }
  NetBIOS::Datagram.bind SMB, body: ->(val) { val.nil? ? SMB::MARKER : val[0..3] == SMB::MARKER }
end

require_relative 'smb/string'
require_relative 'smb/filetime'
require_relative 'smb/blocks'
require_relative 'smb/close'
require_relative 'smb/trans'
require_relative 'smb/nt_create_and_x'
require_relative 'smb/negotiate'
require_relative 'smb/browser'

# If unknown command, bind SMB blocks
PacketGen::Header.add_class PacketGen::Plugin::SMB::Blocks
PacketGen::Plugin::SMB.bind PacketGen::Plugin::SMB::Blocks
