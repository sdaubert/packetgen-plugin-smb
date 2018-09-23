require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB
    describe String do
      describe '#initialize' do
        it 'forces encoding to US-ASCII' do
          str = String.new(unicode: false)
          expect(str.to_human.encoding).to eq(Encoding::ASCII_8BIT)
          expect(str.unicode?).to be(false)
        end
        it 'forces encoding to UTF-16LE' do
          str = String.new(unicode: true)
          expect(str.to_human.encoding).to eq(Encoding::UTF_16LE)
          expect(str.unicode?).to be(true)
          str = String.new
          expect(str.unicode?).to be(true)
        end
      end

      describe '#read' do
        context '(ASCII)' do
          let(:s) { String.new(unicode: false) }
          it 'reads a null terminated BINARY string' do
            s.read("a\x00b\x00c\x00d\x00\x00\x00".force_encoding('BINARY'))
            expect(s.to_human.encoding).to eq(Encoding::ASCII_8BIT)
            expect(s.to_human).to eq('a')
          end

          it 'reads a BINARY string' do
            s.read('ab'.force_encoding('BINARY'))
            expect(s.to_human.encoding).to eq(Encoding::ASCII_8BIT)
            expect(s.to_human).to eq('ab')
          end

          it 'reads a UTF-16LE string' do
            s.read(utf16le('abcd'))
            expect(s.to_human.encoding).to eq(Encoding::ASCII_8BIT)
            expect(s.to_human).to eq('abcd')
          end

          it 'reads a UTF-8 string' do
            s.read('abcd')
            expect(s.to_human.encoding).to eq(Encoding::ASCII_8BIT)
            expect(s.to_human).to eq('abcd')
          end
        end

        context '(unicode)' do
          let(:su) { String.new(unicode: true) }
          it 'reads a double-null terminated BINARY string' do
            su.read("a\x00b\x00c\x00d\x00\x00\x00".force_encoding('BINARY'))
            expect(su.to_human.encoding).to eq(Encoding::UTF_16LE)
            expect(su.to_human).to eq(utf16le('abcd'))
          end

          it 'reads a BINARY string' do
            su.read("a\x00b\x00c\x00d\x00".force_encoding('BINARY'))
            expect(su.to_human.encoding).to eq(Encoding::UTF_16LE)
            expect(su.to_human).to eq(utf16le('abcd'))
          end

          it 'reads a UTF-16LE string' do
            su.read(utf16le('abcd'))
            expect(su.to_human.encoding).to eq(Encoding::UTF_16LE)
            expect(su.to_human).to eq(utf16le('abcd'))
          end

          it 'reads a UTF-8 string' do
            su.read('abcd')
            expect(su.to_human.encoding).to eq(Encoding::UTF_16LE)
            expect(su.to_human).to eq(utf16le('abcd'))
          end
        end
      end
    end
  end
end
