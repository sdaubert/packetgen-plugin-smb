# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  # Server Message Block version 2 and 3 (SMB2) header.
  # @author Sylvain Daubert
  class SMB2 < PacketGen::Header::Base
    # Known commands
    COMMANDS = {
      'negotiate' => 0,
      'session_setup' => 1,
      'logoff' => 2,
      'tree_connect' => 3,
      'tree_disconnect' => 4,
      'create' => 5,
      'close' => 6,
      'flush' => 7,
      'read' => 8,
      'write' => 9,
      'lock' => 10,
      'ioctl' => 11,
      'cancel' => 12,
      'echo' => 13,
      'query_directory' => 14,
      'change_notify' => 15,
      'query_info' => 16,
      'set_info' => 17,
      'oplock_break' => 18
    }.freeze
    # SMB marker, on start of header
    MARKER = PacketGen.force_binary("\xfeSMB").freeze

    # @!attribute protocol
    #  This field must contain {MARKER SMB2 marker}
    #  @return [String]
    define_field :protocol, PacketGen::Types::String, static_length: 4, default: MARKER
    # @!attribute structure_size
    #  16-bit SMB2 header size. Should be 64.
    #  @return [Integer]
    define_field :structure_size, PacketGen::Types::Int16le, default: 64
    # @!attribute credit charge
    #  16-bit credit charge field. Must not be used and must be set to 0.
    #  @return [Integer]
    define_field :credit_charge, PacketGen::Types::Int16le
    # @!attribute status
    #  32-bit status field (SMB 2 dialect only).
    #  @return [Integer]
    define_field :status, PacketGen::Types::Int32le
    # @!attribute command
    #  16-bit command field
    #  @return [Integer]
    define_field :command, PacketGen::Types::Int16leEnum, enum: COMMANDS
    # @!attribute credit
    #  16-bit credit field. This is the number of credits a client is requesting in
    #  a request, and the number of credits granted in a response.
    #  @return [Integer]
    define_field :credit, PacketGen::Types::Int16le
    # @!attribute flags
    #  32-bit flags field
    #  @return [Integer]
    define_field :flags, PacketGen::Types::Int32le
    # @!attribute next_command
    #  32-bit offset from the beginning of this SMB2 header to the start of the subsequent
    #  8-byte aligned SMB2 header (only for compounded requests).
    #  @return [Integer]
    define_field :next_command, PacketGen::Types::Int32le
    # @!attribute message_id
    #  64-bit alue that identifies a message request and response uniquely across all
    #  messages that are sent on the same SMB 2 Protocol transport connection.
    #  @return [Integer]
    define_field :message_id, PacketGen::Types::Int64le
    # @!attribute async_id
    #  64-bit unique ID that is created by the server to handle operations
    #  asynchronously. Only present for asynchronous messages.
    #  @return [Integer]
    define_field :async_id, PacketGen::Types::Int64le, optional: ->(h) { h.flags & 2  == 2}
    # @!attribute reserved
    #  32-bit reserved field.
    #  Only present for synchronous messages.
    #  @return [Integer]
    define_field :reserved, PacketGen::Types::Int32le, optional: ->(h) { (h.flags & 2).zero? }
    # @!attribute tree_id
    #  32-bit integer that uniquely identifies the tree connect for the command.
    #  Only present for synchronous messages.
    #  @return [Integer]
    define_field :tree_id, PacketGen::Types::Int32le, optional: ->(h) { (h.flags & 2).zero? }
    # @!attribute session_id
    #  64-bit integer that uniquely identifies the established session for the command.
    #  @return [Integer]
    define_field :session_id, PacketGen::Types::Int64le
    # @!attribute signature
    #  16-byte message signature
    #  @return [String]
    define_field :signature, PacketGen::Types::String, static_length: 16, default: [0, 0].pack('qq')
    # @!attribute body
    #  @return [String]
    define_field :body, PacketGen::Types::String
    # @!attribute flags_rsv1
    #  2-bit reserved field
    #  @return [Integer]
    # @!attribute flags_smb3_replay_op
    #  When set, the command is a replay operation (only SMB 3 dialect).
    #  @return [Boolean]
    # @!attribute flags_dsf_op
    #  When set, the command is a Distributed File System (DFS) operation..
    #  @return [Boolean]
    # @!attribute flags_rsv2
    #  21-bit reserved field
    #  @return [Integer]
    # @!attribute flags_smb3_priority
    #  3-bit value of I/O priority (only SMB 3 dialect).
    #  @return [Integer]
    # @!attribute flags_signed
    #  When set, the message is signed.
    #  @return [Boolean]
    # @!attribute flags_related_op
    #  When set, the message is a related operation in a compounded chain.
    #  @return [Boolean]
    # @!attribute flags_async
    #  When set, the message is a asynchronous.
    #  @return [Boolean]
    # @!attribute flags_response
    #  When set, the message is a response from server to client.
    #  @return [Boolean]
    define_bit_fields_on :flags, :flags_rsv1, 2, :flags_smb3_replay_op, :flags_dfs_op,
                                 :flags_rsv2, 21, :flags_smb3_priority, 3,
                                 :flags_signed, :flags_related_op, :flags_async,
                                 :flags_response

    # Helper to bind a SMB2 command to {SMB2} header.
    # @param [String] command name
    # @return [void]
    def self.bind_command(command)
      contantized = command.capitalize.gsub(/_(\w)/) { $1.upcase }
      krequest = self.const_get("#{contantized}::Request")
      kresponse = self.const_get("#{contantized}::Response")
      p krequest
      PacketGen::Header.add_class krequest
      self.bind krequest, command: SMB2::COMMANDS[command], flags: ->(v) { v.nil? ? 0 : (v & 1).zero? }
      PacketGen::Header.add_class kresponse
      self.bind kresponse, command: SMB2::COMMANDS[command], flags: ->(v) { v.nil? ? 0 : (v & 1 == 1) }
    end

    # @return [String]
    def inspect
      str = PacketGen::Inspect.dashed_line(self.class, 1)
      fields.each do |attr|
        next if attr == :body

        case attr
        when :flags
          value = bits_on(attr).reject { |_, v| v > 1 }
                               .keys
                               .select { |b| send("#{b}?") }
                               .map(&:to_s)
                               .join(',')
                               .gsub!(/#{attr}_/, '')
          value = '%-16s (0x%02x)' % [value, self[attr].to_i]
          str << PacketGen::Inspect.shift_level(1)
          str << PacketGen::Inspect::FMT_ATTR % [self[attr].class.to_s.sub(/.*::/, ''),
                                                 attr, value]
        else
          str << PacketGen::Inspect.inspect_attribute(attr, self[attr], 1)
        end
      end
      str
    end
  end
  # TODO: move this in netbios file when packetgen3 will be out
  PacketGen::Header::TCP.bind PacketGen::Header::NetBIOS::Session, dport: 445
  PacketGen::Header::TCP.bind PacketGen::Header::NetBIOS::Session, sport: 445

  PacketGen::Header.add_class SMB2
  PacketGen::Header::NetBIOS::Session.bind SMB2, body: ->(val) { val.nil? ? SMB2::MARKER : val[0..3] == SMB2::MARKER }
  PacketGen::Header::NetBIOS::Datagram.bind SMB2, body: ->(val) { val.nil? ? SMB2::MARKER : val[0..3] == SMB2::MARKER }
end

require_relative 'smb2/base'
require_relative 'smb2/error'
require_relative 'smb2/negotiate'
