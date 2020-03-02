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

  spec.required_ruby_version = '>= 2.3.0'

  spec.add_dependency 'packetgen', '~>3.1', '>=3.1.2'
  spec.add_dependency 'rasn1', '~>0.6', '>= 0.6.8'

  spec.add_development_dependency 'bundler', '>=1.17', '<3'
  spec.add_development_dependency 'rake', '~> 12.3'
  spec.add_development_dependency 'rspec', '~> 3.7'
  spec.add_development_dependency 'rubocop', '~> 0.79'
  spec.add_development_dependency 'rubocop-performance', '~> 1.5'
  spec.add_development_dependency 'simplecov', '~> 0.16'
  spec.add_development_dependency 'yard', '~> 0.9'
end
