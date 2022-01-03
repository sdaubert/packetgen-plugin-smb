require_relative 'spec_helper'

module PacketGen::Plugin
  describe GSSAPI do
    let(:pkts) { read_raw_packets('smb2.pcapng') }
    let(:legacy_init_pkt) { PacketGen.parse(read_raw_packets('smb2-nego.pcapng')[7]) }

    it 'parses an initial context blob' do
      gssapi = PacketGen.parse(pkts[3]).smb2_negotiate_response.buffer
      expect(gssapi).to be_a(GSSAPI)
      expect(gssapi.chosen).to eq(0)
      expect(gssapi[:init_env][:oid].value).to eq('1.3.6.1.5.5.2')
      expect(gssapi[:init_env][:token_init][:mech_types].value.size).to eq(2)
      expect(gssapi[:init_env][:token_init][:mech_types][0].value).to eq('1.3.6.1.4.1.311.2.2.30')
      expect(gssapi[:init_env][:token_init][:mech_types][1].value).to eq('1.3.6.1.4.1.311.2.2.10')
      expect(gssapi[:init_env][:token_init][:mech_token].value).to start_with("NEGOEXTS\x01")
      expect(gssapi[:init_env][:token_init][:mech_token].value).to end_with("\x18Token Signing Public Key")
      expect(gssapi[:init_env][:token_init][:mech_token].value.length).to eq(264)
    end

    it 'parses legacy initial context blob' do
      gssapi = legacy_init_pkt.smb2_negotiate_response.buffer
      expect(gssapi).to be_a(GSSAPI)
      expect(gssapi.chosen).to eq(0)
      expect(gssapi[:init_env][:oid].value).to eq('1.3.6.1.5.5.2')
      expect(gssapi[:init_env][:token_init][:mech_types].value.size).to eq(5)
      expect(gssapi[:init_env][:token_init][:mech_types][0].value).to eq('1.3.6.1.4.1.311.2.2.30')
      expect(gssapi[:init_env][:token_init][:mech_types][1].value).to eq('1.2.840.48018.1.2.2')
      expect(gssapi[:init_env][:token_init][:mech_types][2].value).to eq('1.2.840.113554.1.2.2')
      expect(gssapi[:init_env][:token_init][:mech_types][3].value).to eq('1.2.840.113554.1.2.2.3')
      expect(gssapi[:init_env][:token_init][:mech_types][4].value).to eq('1.3.6.1.4.1.311.2.2.10')
      str = force_binary("\xA3\e0\x19\xA0\x17\e\x15Server2008@SMB3.local")
      expect(gssapi[:init_env][:token_init][:mech_list_mic].value).to eq(str)
    end

    it 'parses a non-initial context blob' do
      gssapi = PacketGen.parse(pkts[5]).smb2_sessionsetup_response.buffer
      expect(gssapi).to be_a(GSSAPI)
      expect(gssapi.chosen).to eq(1)
      expect(gssapi[:token_resp][:negstate].value).to eq('accept-incomplete')
      expect(gssapi[:token_resp][:supported_mech].value).to eq('1.3.6.1.4.1.311.2.2.10')
      expect(gssapi[:token_resp][:response].to_der.size).to eq(0xf4)
    end

    it 'parses a result blob' do
      gssapi = PacketGen.parse(pkts[7]).smb2_sessionsetup_response.buffer
      expect(gssapi).to be_a(GSSAPI)
      expect(gssapi.chosen).to eq(1)
      expect(gssapi[:token_resp][:negstate].value).to eq('accept-completed')
    end
  end
end
