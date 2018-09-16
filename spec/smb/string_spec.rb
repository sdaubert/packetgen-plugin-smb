require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB
    describe String do
      describe '#initialize' do
        it 'forces encoding to UTF-16LE' do
          expect(String.new.to_human.encoding).to eq(Encoding::UTF_16LE)
        end
      end

      describe '#read' do
        let(:s) { String.new }
        it 'reads a double-null terminated BINARY string' do
          s.read("a\x00b\x00c\x00d\x00\x00\x00".force_encoding('BINARY'))
          expect(s.to_human.encoding).to eq(Encoding::UTF_16LE)
          expect(s.to_human).to eq(utf16le('abcd'))
        end

        it 'reads a BINARY string' do
          s.read("a\x00b\x00c\x00d\x00".force_encoding('BINARY'))
          expect(s.to_human.encoding).to eq(Encoding::UTF_16LE)
          expect(s.to_human).to eq(utf16le('abcd'))
        end

        it 'reads a UTF-16LE string' do
          s.read(utf16le('abcd'))
          expect(s.to_human.encoding).to eq(Encoding::UTF_16LE)
          expect(s.to_human).to eq(utf16le('abcd'))
        end

        it 'reads a UTF-8 string' do
          s.read('abcd')
          expect(s.to_human.encoding).to eq(Encoding::UTF_16LE)
          expect(s.to_human).to eq(utf16le('abcd'))
        end
      end
    end
  end
end
