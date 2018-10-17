require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB2
    pkts = read_packets('smb2.pcapng')

    describe SessionSetup::Request do
      it 'parses a SMB2 Session Setup request packet #1' do
        pkt = pkts[4]
        expect(pkt.is?('SMB2')).to be(true)
        expect(pkt.smb2.command).to eq(1)
        expect(pkt.smb2[:command].to_human).to eq('session_setup')
        expect(pkt.smb2.flags_response?).to be(false)
        expect(pkt.is?('SMB2::SessionSetup::Request')).to be(true)
        ssr = pkt.smb2_sessionsetup_request
        expect(ssr.structure_size).to eq(25)
        expect(ssr.flags).to eq(0)
        expect(ssr.security_mode).to eq(1)
        expect(ssr[:security_mode].to_human).to eq('signing_enabled')
        expect(ssr.capabilities).to eq(1)
        expect(ssr.cap_dfs?).to be(true)
        expect(ssr.channel).to eq(0)
        expect(ssr.prev_session_id).to eq(0)
        expect(ssr.buffer_offset).to eq(0x58)
        expect(ssr.buffer_length).to eq(74)
        expect(ssr.buffer.sz).to eq(74)
        expect(ssr.buffer.chosen).to eq(0)
      end

      it 'parses a SMB2 Session Setup request packet #1' do
        pkt = pkts[6]
        expect(pkt.is?('SMB2')).to be(true)
        expect(pkt.smb2.command).to eq(1)
        expect(pkt.smb2[:command].to_human).to eq('session_setup')
        expect(pkt.smb2.flags_response?).to be(false)
        expect(pkt.is?('SMB2::SessionSetup::Request')).to be(true)
        ssr = pkt.smb2_sessionsetup_request
        expect(ssr.structure_size).to eq(25)
        expect(ssr.flags).to eq(0)
        expect(ssr.security_mode).to eq(1)
        expect(ssr.capabilities).to eq(1)
        expect(ssr.channel).to eq(0)
        expect(ssr.prev_session_id).to eq(0)
        expect(ssr.buffer_offset).to eq(0x58)
        expect(ssr.buffer_length).to eq(526)
        expect(ssr.buffer.sz).to eq(526)
        expect(ssr.buffer.chosen).to eq(1)
        expect(ssr.buffer[:token_resp][:response].to_der.size).to eq(0x1f2)
        expect(ssr.buffer[:token_resp][:response].value).to start_with("NTLMSSP")
        expect(ssr.buffer[:token_resp][:mech_list_mic].to_der.size).to eq(20)
        expect(ssr.buffer[:token_resp][:mech_list_mic].value.size).to eq(16)
      end
    end

    describe SessionSetup::Response do
      it 'parses a SMB2 Session Setup response packet' do
        pkt = pkts[5]
        expect(pkt.is?('SMB2')).to be(true)
        expect(pkt.smb2.command).to eq(1)
        expect(pkt.smb2[:command].to_human).to eq('session_setup')
        expect(pkt.smb2.status).to eq(0xc0000016)
        expect(pkt.smb2.flags_response?).to be(true)
        expect(pkt.is?('SMB2::SessionSetup::Response')).to be(true)
        ssr = pkt.smb2_sessionsetup_response
        expect(ssr.structure_size).to eq(9)
        expect(ssr.flags).to eq(0)
        expect(ssr.buffer_offset).to eq(0x48)
        expect(ssr.buffer_length).to eq(271)
        expect(ssr.buffer.sz).to eq(271)
        expect(ssr.buffer.chosen).to eq(1)
        expect(ssr.buffer[:token_resp][:negstate].value).to eq('accept-incomplete')
      end
    end
  end
end
