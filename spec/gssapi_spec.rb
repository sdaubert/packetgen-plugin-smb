require_relative 'spec_helper'

module PacketGen::Plugin
  describe GSSAPI do
    let(:gssapi) { read_packets('smb2.pcapng')[3].smb2_negotiate_response.buffer }

    it 'parses a blob' do
      expect(gssapi).to be_a(GSSAPI)
      expect(gssapi[:oid].value).to eq('1.3.6.1.5.5.2')
      expect(gssapi[:token][:mech_types].value.size).to eq(2)
      expect(gssapi[:token][:mech_types][0].value).to eq('1.3.6.1.4.1.311.2.2.30')
      expect(gssapi[:token][:mech_types][1].value).to eq('1.3.6.1.4.1.311.2.2.10')
      expect(gssapi[:token][:mech_token].value).to start_with("NEGOEXTS\x01")
      expect(gssapi[:token][:mech_token].value).to end_with("\x18Token Signing Public Key")
      expect(gssapi[:token][:mech_token].value.length).to eq(264)
   end
  end
end
