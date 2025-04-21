require_relative '../spec_helper'

module PacketGen::Plugin
  class NTLM
    describe Challenge do
      let(:raw_pkt) { read_raw_packets('smb2.pcapng')[5] }
      let(:raw_str) { PacketGen.parse(raw_pkt).smb2_sessionsetup_response.buffer[:token_resp][:response].value }

      describe '#read' do
        let(:challenge) { Challenge.new.read(raw_str) }

        it 'parses a binary string' do
          expect(challenge.signature).to eq(SIGNATURE)
          expect(challenge.type).to eq(2)
          expect(challenge.target_name_len).to eq(30)
          expect(challenge.target_name_maxlen).to eq(30)
          expect(challenge.target_name_offset).to eq(56)
          expect(challenge.flags).to eq(0x628a8215)
          expect(challenge.challenge).to eq([0xa5daa42b_ce0a85f7].pack('q>'))
          expect(challenge.reserved).to eq(0)
          expect(challenge.target_info_len).to eq(152)
          expect(challenge.target_info_maxlen).to eq(152)
          expect(challenge.target_info_offset).to eq(86)
          expect(challenge.version).to eq([10, 0, 0xab, 0x3f, 0, 0, 0, 15].pack('C*'))
          expect(challenge.payload.size).to eq(182)
        end

        it 'sets target_name' do
          expect(challenge.target_name).to eq(utf16le('DESKTOP-30HMVIQ'))
        end

        it 'sets target_info' do
          expect(challenge.target_info.size).to eq(6)
          expect(challenge.target_info[0]).to be_a(AvPair)
          expect(challenge.target_info[0].human_type).to eq('DomainName')
          expect(challenge.target_info[0].value).to eq('DESKTOP-30HMVIQ')
          expect(challenge.target_info[1]).to be_a(AvPair)
          expect(challenge.target_info[1].human_type).to eq('ComputerName')
          expect(challenge.target_info[1].value).to eq('DESKTOP-30HMVIQ')
          expect(challenge.target_info[2]).to be_a(AvPair)
          expect(challenge.target_info[2].human_type).to eq('DnsDomainName')
          expect(challenge.target_info[2].value).to eq('DESKTOP-30HMVIQ')
          expect(challenge.target_info[3]).to be_a(AvPair)
          expect(challenge.target_info[3].human_type).to eq('DnsComputerName')
          expect(challenge.target_info[3].value).to eq('DESKTOP-30HMVIQ')
          expect(challenge.target_info[4]).to be_a(TimestampAvPair)
          expect(challenge.target_info[4].human_type).to eq('Timestamp')
          expect(challenge.target_info[4].value).to eq('2018-10-04 18:13:04.467800000 UTC')
          expect(challenge.target_info[5]).to be_a(EOLAvPair)
          expect(challenge.target_info[5].human_type).to eq('EOL')
          expect(challenge.target_info[5].value).to eq('')
        end
      end

      describe '#to_s' do
        let(:challenge) { Challenge.new }

        it 'returns a string' do
          str = 'NTLMSSP'.b << [0, 2, 0, 0, 0, 0, 0, 0].pack('CL<QLQQQQ')
          expect(challenge.to_s).to eq(str)
        end

        it 'sets target name in output (no unicode)' do
          challenge.target_name.read('MYNAME')
          challenge.calc_length
          expect(challenge.to_s).to end_with('MYNAME')
        end

        it 'sets target name in output (unicode)' do
          challenge.flags_a = true
          challenge.target_name.read('MYNAME')
          challenge.calc_length
          expect(challenge.to_s).to end_with(utf16le('MYNAME').b)
        end

        it 'sets target info in output (no unicode)' do
          challenge.target_info << { type: 'DomainName', value: 'DESKTOP-1234567' }
          challenge.target_info << { type: 'EOL', length: 0 }
          challenge.calc_length
          expect(challenge.to_s).to end_with("DESKTOP-1234567\x00\x00\x00\x00".b)
        end

        it 'sets target info in output (unicode)' do
          challenge.flags = 1
          challenge.target_info << { type: 'DomainName', value: 'DESKTOP-1234567' }
          challenge.target_info << { type: 'EOL', length: 0 }
          challenge.calc_length
          expect(challenge.to_s).to end_with(utf16le('DESKTOP-1234567').b << "\x00".b * 4)
        end
      end
    end
  end
end
