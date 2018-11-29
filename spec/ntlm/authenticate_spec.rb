module PacketGen::Plugin
  class NTLM
    describe Authenticate do
      let(:raw_pkt) { read_raw_packets('smb2.pcapng')[6] }
      let(:raw_str) { PacketGen.parse(raw_pkt).smb2_sessionsetup_request.buffer[:token_resp][:response].value }

      describe '#read' do
        let(:auth) { Authenticate.new.read(raw_str) }

        it 'parses a binary string' do
          expect(auth.signature).to eq(SIGNATURE)
          expect(auth.type).to eq(3)
          expect(auth.lm_response_len).to eq(24)
          expect(auth.lm_response_maxlen).to eq(24)
          expect(auth.lm_response_offset).to eq(88)
          expect(auth.nt_response_len).to eq(314)
          expect(auth.nt_response_maxlen).to eq(314)
          expect(auth.nt_response_offset).to eq(112)
          expect(auth.domain_name_len).to eq(18)
          expect(auth.domain_name_maxlen).to eq(18)
          expect(auth.domain_name_offset).to eq(426)
          expect(auth.user_name_len).to eq(14)
          expect(auth.user_name_maxlen).to eq(14)
          expect(auth.user_name_offset).to eq(444)
          expect(auth.workstation_len).to eq(16)
          expect(auth.workstation_maxlen).to eq(16)
          expect(auth.workstation_offset).to eq(458)
          expect(auth.session_key_len).to eq(16)
          expect(auth.session_key_maxlen).to eq(16)
          expect(auth.session_key_offset).to eq(474)
          expect(auth.flags).to eq(0x62088215)
          expect(auth.version).to eq([6, 1, 0, 0, 0, 0, 0, 15].pack('C*'))
          mic = force_binary("\xf4\xc3\x75\xc2\x4f\xa0\x44\xec\xf6\xc6\x4b\x07\xab\x1b\x5e\x3e")
          expect(auth.mic).to eq(mic)
        end

        it 'sets lm_response' do
          expect(auth.lm_response).to eq(force_binary("\0" * 24))
        end

        it 'sets nt_response' do
          expect(auth.nt_response).to be_a(Ntlmv2Response)

          n2r = auth.nt_response
          expect(n2r.type).to eq(1)
          expect(n2r.hi_type).to eq(1)
          expect(n2r.reserved1).to eq(0)
          expect(n2r.reserved2).to eq(0)
          expect(n2r.timestamp).to eq('2018-10-04 18:13:04.467800000 UTC')
          expect(n2r.client_challenge).to eq([0x01505ee9, 0x6aa1b71d].pack('N*'))
          expect(n2r.reserved3).to eq(0)
          expect(n2r.avpairs.size).to eq(10)
          names = n2r.avpairs.map { |pair| pair.human_type }
          expect(names).to eq(%w[DomainName ComputerName DnsDomainName DnsComputerName Timestamp Flags SingleHost ChannelBindings TargetName EOL])
        end

        it 'sets domain_name' do
          expect(auth.domain_name).to eq(utf16le('WORKGROUP'))
        end

        it 'sets user_name' do
          expect(auth.user_name).to eq(utf16le('sylvain'))
        end

        it 'sets workstation' do
          expect(auth.workstation).to eq(utf16le('LANFEUST'))
        end

        it 'sets session_key' do
          key = [0x3a0e, 0x4143, 0xea16, 0x04c8, 0x4ec2, 0x499f, 0xf729, 0x112c].pack('n*')
          expect(auth.session_key).to eq(key)
        end
      end
    end
  end
end
