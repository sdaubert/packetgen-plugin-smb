require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB
    describe String do
      describe '#initialize' do
        it 'forces encoding to US-ASCII' do
          str = String.new(unicode: false)
          expect(str.encoding).to eq(Encoding::ASCII_8BIT)
          expect(str.unicode?).to be(false)
        end
        it 'forces encoding to UTF-16LE' do
          str = String.new(unicode: true)
          expect(str.encoding).to eq(Encoding::UTF_16LE)
          expect(str.unicode?).to be(true)
          str = SMB::String.new
          expect(str.unicode?).to be(true)
        end
      end

      describe '#read' do
        context '(ASCII)' do
          let(:s) { String.new(unicode: false) }

          it 'reads a null terminated BINARY string' do
            s.read("a\x00b\x00c\x00d\x00\x00\x00".force_encoding('BINARY'))
            expect(s.encoding).to eq(Encoding::ASCII_8BIT)
            expect(s.to_human).to eq('a')
          end

          it 'reads a BINARY string' do
            s.read('ab'.force_encoding('BINARY'))
            expect(s.encoding).to eq(Encoding::ASCII_8BIT)
            expect(s.to_human).to eq('ab')
          end

          it 'reads a UTF-16LE string' do
            s.read(utf16le('abcd'))
            expect(s.encoding).to eq(Encoding::ASCII_8BIT)
            expect(s.to_human).to eq('abcd')
          end

          it 'reads a UTF-8 string' do
            s.read('abcd')
            expect(s.encoding).to eq(Encoding::ASCII_8BIT)
            expect(s.to_human).to eq('abcd')
          end
        end

        context '(unicode)' do
          let(:su) { String.new(unicode: true) }
          it 'reads a double-null terminated BINARY string' do
            su.read("a\x00b\x00c\x00d\x00\x00\x00".force_encoding('BINARY'))
            expect(su.encoding).to eq(Encoding::UTF_16LE)
            expect(su.to_human).to eq('abcd')
          end

          it 'reads a BINARY string' do
            su.read("a\x00b\x00c\x00d\x00".force_encoding('BINARY'))
            expect(su.encoding).to eq(Encoding::UTF_16LE)
            expect(su.to_human).to eq('abcd')
          end

          it 'reads a UTF-16LE string' do
            su.read(utf16le('abcd'))
            expect(su.encoding).to eq(Encoding::UTF_16LE)
            expect(su.to_human).to eq('abcd')
          end

          it 'reads a UTF-8 string' do
            su.read('abcd')
            expect(su.encoding).to eq(Encoding::UTF_16LE)
            expect(su.to_human).to eq('abcd')
          end
        end
      end

      describe '#to_s' do
        context '(ASCII)' do
          it 'does set a null-byte if string is not null-terminated' do
            s = String.new(unicode: false, null_terminated: false)
            s.read('abcd'.force_encoding('BINARY'))
            expect(s.to_s).to eq('abcd')

            s.read("abcd\x00".force_encoding('BINARY'))
            expect(s.to_s).to eq('abcd')
          end

          it 'sets a null terminator if strinf is null-terminated' do
            s = String.new(unicode: false, null_terminated: true)
            s.read('abcd'.force_encoding('BINARY'))
            expect(s.to_s).to eq("abcd\x00")

            s.read("abcd\x00".force_encoding('BINARY'))
            expect(s.to_s).to eq("abcd\x00")
          end
        end

        context '(unicode)' do
          it 'does set a null-byte if string is not null-terminated' do
            s = String.new(null_terminated: false)
            s.read('abcd'.force_encoding('BINARY'))
            expect(s.to_s).to eq(force_binary('abcd'))

            s.read(utf16le("abcd\x00"))
            expect(s.to_s).to eq(force_binary(utf16le('abcd')))
            s.read(utf16le("abcd\x00").force_encoding('BINARY'))
            expect(s.to_s).to eq(force_binary(utf16le('abcd')))
          end

          it 'sets a null terminator if strinf is null-terminated' do
            s = String.new(null_terminated: true)
            s.read('abcd'.force_encoding('BINARY'))
            expect(s.to_s).to eq(force_binary("abcd\x00\x00"))
            s.read(utf16le('abcd'))
            expect(s.to_s).to eq(force_binary(utf16le("abcd\x00")))

            s.read(utf16le("abcd\x00").force_encoding('BINARY'))
            expect(s.to_s).to eq(force_binary(utf16le("abcd\x00")))
          end
        end
      end
    end
  end
end
