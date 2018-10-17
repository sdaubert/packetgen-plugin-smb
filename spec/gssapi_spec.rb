require_relative 'spec_helper'

module PacketGen::Plugin
  describe GSSAPI do
    let(:pkts) { read_packets('smb2.pcapng') }

    it 'parses an initial context blob' do
      gssapi = pkts[3].smb2_negotiate_response.buffer
      expect(gssapi).to be_a(GSSAPI)
      expect(gssapi.chosen).to eq(0)
      expect(gssapi[:oid].value).to eq('1.3.6.1.5.5.2')
      expect(gssapi[:token_init][:mech_types].value.size).to eq(2)
      expect(gssapi[:token_init][:mech_types][0].value).to eq('1.3.6.1.4.1.311.2.2.30')
      expect(gssapi[:token_init][:mech_types][1].value).to eq('1.3.6.1.4.1.311.2.2.10')
      expect(gssapi[:token_init][:mech_token].value).to start_with("NEGOEXTS\x01")
      expect(gssapi[:token_init][:mech_token].value).to end_with("\x18Token Signing Public Key")
      expect(gssapi[:token_init][:mech_token].value.length).to eq(264)
    end

    it 'parses a non-initial context blob' do
      p pkts[5]
      gssapi = pkts[5].smb2_sessionsetup_response.buffer
      expect(gssapi).to be_a(GSSAPI)
      expect(gssapi.chosen).to eq(1)
      expect(gssapi[:token_resp][:negstate].value).to eq('accept-incomplete')
      expect(gssapi[:token_resp][:supported_mech].value).to eq('1.3.6.1.4.1.311.2.2.10')
      expect(gssapi[:token_resp][:response].to_der.size).to eq(0xf4)
    end

    it 'parses a result blob' do
      gssapi = pkts[7].smb2_sessionsetup_response.buffer
      expect(gssapi).to be_a(GSSAPI)
      expect(gssapi.chosen).to eq(1)
      expect(gssapi[:token_resp][:negstate].value).to eq('accept-completed')
    end
  end
end
