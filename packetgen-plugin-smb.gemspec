# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'packetgen/plugin/smb_version'

Gem::Specification.new do |spec|
  spec.name          = 'packetgen-plugin-smb'
  spec.version       = PacketGen::Plugin::SMB_VERSION
  spec.authors       = ['Sylvain Daubert']
  spec.email         = ['sylvain.daubert@laposte.net']

  spec.summary       = 'SMB plugin for packetgen.'
  spec.homepage      = 'https://github.com/sdaubert/packetgen-plugin-smb'

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir = 'bin'
  spec.executables = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = %w[lib]

  spec.required_ruby_version = '>= 2.5.0'

  spec.add_dependency 'packetgen', '~>3.2', '>=3.2.1'
  spec.add_dependency 'rasn1', '~>0.8', '>= 0.8.0'
end
