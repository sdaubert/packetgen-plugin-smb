[![Gem Version](https://badge.fury.io/rb/packetgen-plugin-smb.svg)](https://badge.fury.io/rb/packetgen-plugin-smb)
[![Build Status](https://travis-ci.com/sdaubert/packetgen-plugin-smb.svg?branch=master)](https://travis-ci.com/sdaubert/packetgen-plugin-smb)

# Packetgen::Plugin::SMB

This is a plugin for [PacketGen gem](https://github.com/sdaubert/packetgen). It adds some support for SMB protocol suite:

* SMB:
    * SMB common header,
    * Close command,
    * NtCreateAndX command,
    * Trans command,
    * Browser subprotocol,
* SMB2:
    * SMB2 common header (support 2.x and 3.x dialects),
    * Negotiate command,
    * SessionSetup command,
* GSSAPI, used to transport negotiation over SMB2 commands.


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

TODO

## See also

API documentation: http://www.rubydoc.info/gems/packetgen-plugin-smb

## License

MIT License (see [LICENSE](https://github.com/sdaubert/packetgen-plugin-smb/blob/master/LICENSE))

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sdaubert/packetgen-plugin-smb.
