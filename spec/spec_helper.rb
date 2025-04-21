# frozen_string_literal: true

begin
  require 'simplecov'
  SimpleCov.start do
    add_filter '/spec/'
    add_filter '/vendor/'
  end
rescue LoadError
  # No simplecov
end

$LOAD_PATH.unshift File.join(File.dirname(__FILE__), '..', 'lib')
require 'packetgen-plugin-smb'

Dir["#{File.dirname(__FILE__)}/support/**/*.rb"].sort.each { |f| require f }
RSpec.configure do |c|
  c.include BindingHelper
  c.include StringHelper
end

def read_packets(filename)
  PacketGen::PcapNG::File.new.read_packets(File.join(__dir__, filename))
end

def read_raw_packets(filename)
  PacketGen::PcapNG::File.new.read_packet_bytes(File.join(__dir__, filename))
end
