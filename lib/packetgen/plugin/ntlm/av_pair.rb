# This file is part of packetgen-plugin-smb.
# See https://github.com/sdaubert/packetgen-plugin-smb for more informations
# Copyright (C) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

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

      def read(str)
        super

        stop = each_with_index do |avpair, i|
                 next unless avpair.type.zero?

                 break i + 1
               end
        return self if stop.nil? || (stop >= size)

        @array[stop..-1] = []
        self
      end

      private

      def real_type(obj)
        case obj.type
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
