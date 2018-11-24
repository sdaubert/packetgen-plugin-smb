require_relative 'spec_helper'

module PacketGen::Plugin
  describe NTLM do
    describe '.read' do
      it 'parses and decode a Negotiate message' do
        raw_pkt = read_raw_packets('smb2.pcapng')[4]
        raw_nego_str = PacketGen.parse(raw_pkt).smb2_sessionsetup_request.buffer[:token_init][:mech_token].value
        expect(NTLM.read(raw_nego_str)).to be_a(NTLM::Negotiate)
      end

      it 'parses and decode a Challenge message'
      it 'parses and decode a Auth message'
    end
  end
end
