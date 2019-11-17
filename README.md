[![Gem Version](https://badge.fury.io/rb/packetgen-plugin-smb.svg)](https://badge.fury.io/rb/packetgen-plugin-smb)
[![Build Status](https://travis-ci.com/sdaubert/packetgen-plugin-smb.svg?branch=master)](https://travis-ci.com/sdaubert/packetgen-plugin-smb)

# Packetgen::Plugin::SMB

This is a plugin for [PacketGen gem](https://github.com/sdaubert/packetgen). It adds some support for SMB protocol suite:

* NetBIOS:
  * Datagram service,
  * Session service,
* SMB:
  * SMB common header,
  * Negotiate command,
  * Close command,
  * NtCreateAndX command,
  * Trans command,
  * Browser subprotocol,
* SMB2:
  * SMB2 common header (support 2.x and 3.x dialects),
  * Negotiate command,
  * SessionSetup command,
* GSSAPI, used to transport negotiation over SMB2 commands,
* NTLM, SMB authentication protocol,
* LLMNR (_Link-Local Multicast Name Resolution_), resolution protocol used in SMB networks.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'packetgen-plugin-smb'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install packetgen-plugin-smb

## Usage

### LLMNR

LLMNR is a multicast protocol. Unless you want to have a fine control on UDP layer, the simplest way is to use it over a UDP ruby socket:

```ruby
require 'socket'
require 'packetgen'
require 'packetgen-plugin-smb'

LLMNR_MCAST_ADDR = '224.0.0.252'
LOCAL_IPADDR = 'x.x.x.x' # your IP

# Open a UDP socket
socket = UDPSocket.new
# Bind it to receive LLMNR response packets
socket.bind(LOCAL_IPADDR, 0)

# Send a LLMNR query
query = PacketGen.gen('LLMNR', id: 0x1234, opcode: 'query')
query.llmnr.qd << { rtype: 'Question', name: 'example.local' }
socket.send(query.to_s, 0, LLMNR_MCAST_ADDR, PacketGen::Plugin::LLMNR::UDP_PORT)

# Get answer
# data = socket.recv(1024)
data, peer = socket.recvfrom(1024)
answer = PacketGen.parse(data, first_header: 'LLMNR')
example_local_ip = answer.llmnr.an.to_a
                         .find { |an| an.is_a?(PacketGen::Header::DNS::RR) }.human_rdata
puts example_local_ip
```

You have to manage multicast if you want to make a LLMNR responder. For further details, see [examples/llmnr-responder](/examples/llmnr-responder).

## See also

API documentation: http://www.rubydoc.info/gems/packetgen-plugin-smb

## License

MIT License (see [LICENSE](https://github.com/sdaubert/packetgen-plugin-smb/blob/master/LICENSE))

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sdaubert/packetgen-plugin-smb.
