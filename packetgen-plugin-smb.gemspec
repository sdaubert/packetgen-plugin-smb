lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'packetgen/plugin/smb_version'

Gem::Specification.new do |spec|
  spec.name          = 'packetgen-plugin-smb'
  spec.version       = PacketGen::Plugin::SMB_VERSION
  spec.authors       = ['Sylvain Daubert']
  spec.email         = ['sylvain.daubert@laposte.net']

  spec.summary       = %q{SMB plugin for packetgen.}
  #spec.description   = %q{TODO: Write a longer description or delete this line.}
  spec.homepage      = 'https://github.com/sdaubert/packetgen-plugin-smb'

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.require_paths = ['lib']

  spec.add_dependency 'packetgen', '~>2.8', '>= 2.8.1'

  spec.add_development_dependency 'bundler', '~> 1.16'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.7'
  spec.add_development_dependency 'simplecov', '~> 0.16'
  spec.add_development_dependency 'yard', '~> 0.9'


end
