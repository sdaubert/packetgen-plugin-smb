# frozen_string_literal: true

# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class NTLM
    # Known AvPair IDs
    AVPAIR_TYPES = {
      'EOL' => 0,
      'ComputerName' => 1,
      'DomainName' => 2,
      'DnsComputerName' => 3,
      'DnsDomainName' => 4,
      'DnsTreeName' => 5,
      'Flags' => 6,
      'Timestamp' => 7,
      'SingleHost' => 8,
      'TargetName' => 9,
      'ChannelBindings' => 10
    }.freeze

    # AVPAIR structure, with value of type {SMB::String}.
    AvPair = PacketGen::Types::AbstractTLV.create(type_class: PacketGen::Types::Int16leEnum,
                                                  length_class: PacketGen::Types::Int16le,
                                                  value_class: SMB::String)
    AvPair.define_type_enum AVPAIR_TYPES

    class AvPair
      def initialize(options={})
        super
        self[:value] = self[:value].class.new(null_terminated: false).read(self.value)
      end
    end

    # EOL AVPAIR structure, with no value
    EOLAvPair = PacketGen::Types::AbstractTLV.create(type_class: PacketGen::Types::Int16leEnum,
                                                     length_class: PacketGen::Types::Int16le)
    EOLAvPair.define_type_enum AVPAIR_TYPES

    # Timestamp AVPAIR structure, with value of type {SMB::Filetime}.
    TimestampAvPair = PacketGen::Types::AbstractTLV.create(type_class: PacketGen::Types::Int16leEnum,
                                                           length_class: PacketGen::Types::Int16le,
                                                           value_class: SMB::Filetime)
    TimestampAvPair.define_type_enum AVPAIR_TYPES

    # Int32le AVPAIR structure, with value a {PacketGen::Types::Int32le}.
    Int32leAvPair = PacketGen::Types::AbstractTLV.create(type_class: PacketGen::Types::Int16leEnum,
                                                         length_class: PacketGen::Types::Int16le,
                                                         value_class: PacketGen::Types::Int32le)
    Int32leAvPair.define_type_enum AVPAIR_TYPES

    # String AVPAIR structure, with value a {PacketGen::Types::String}.
    StringAvPair = PacketGen::Types::AbstractTLV.create(type_class: PacketGen::Types::Int16leEnum,
                                                        length_class: PacketGen::Types::Int16le,
                                                        value_class: PacketGen::Types::String)
    StringAvPair.define_type_enum AVPAIR_TYPES

    # Specialized array containing {AvPair AvPairs}.
    class ArrayOfAvPair < PacketGen::Types::Array
      set_of AvPair

      # Get unicode property
      # @return [Boolean]
      attr_reader :unicode
      alias unicode? unicode

      # Set unicode property
      # @param [Boolean] unicode
      # @return [Boolean]
      def unicode=(unicode)
        @unicode = unicode
        each { |avpair| avpair.value.unicode = unicode if avpair.value.respond_to? :unicode= }
        unicode
      end

      # @return [String]
      def to_s
        self.unicode = unicode
        super
      end

      private

      def record_from_hash(hsh)
        obj = AvPair.new(type: hsh[:type])
        klass = real_type(obj)

        avpair = klass.new
        avpair.type = hsh[:type]
        avpair[:value].unicode = unicode? if avpair[:value].respond_to?(:unicode=)
        avpair[:value].read(hsh[:value])
        avpair.length = hsh[:length] || avpair[:value].sz
        avpair
      end

      def real_type(obj)
        case obj.type
        when AVPAIR_TYPES['EOL']
          EOLAvPair
        when AVPAIR_TYPES['Timestamp']
          TimestampAvPair
        when AVPAIR_TYPES['Flags']
          Int32leAvPair
        when AVPAIR_TYPES['SingleHost'], AVPAIR_TYPES['ChannelBindings']
          StringAvPair
        else
          AvPair
        end
      end
    end
  end
end
