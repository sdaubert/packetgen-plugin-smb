require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB
    module Negotiate
      pkt_req = read_packets('smb2.pcapng').first

      describe Request do
        it 'parses a SMB NEGOTIATE request packet' do
          expect(pkt_req.is?('NetBIOS::Session')).to be(true)
          expect(pkt_req.is?('SMB')).to be(true)
          expect(pkt_req.smb[:command].to_human).to eq('negotiate')
          expect(pkt_req.smb.flags_reply?).to be(false)
          expect(pkt_req.is?('SMB::Negotiate::Request')).to be(true)
          expect(pkt_req.smb.body).to be_a(SMB::Negotiate::Request)
          expect(pkt_req.smb_negotiate_request.word_count).to eq(0)
          expect(pkt_req.smb_negotiate_request.byte_count).to eq(177)
          expect(pkt_req.smb_negotiate_request.dialects.size).to eq(12)
          expect(pkt_req.smb_negotiate_request.dialects.map(&:format).uniq).to eq([2])

          ary = pkt_req.smb_negotiate_request.dialects.map(&:dialect).map(&:to_str)
          ary.map! { |str| str.encode('UTF-8') }
          expect(ary).to eq(['PC NETWORK PROGRAM 1.0',
                             'MICROSOFT NETWORKS 1.03',
                             'MICROSOFT NETWORKS 3.0',
                             'LANMAN1.0',
                             'LM1.2X002',
                             'DOS LANMAN2.1',
                             'LANMAN2.1',
                             'Samba',
                             'NT LANMAN 1.0',
                             'NT LM 0.12',
                             'SMB 2.002',
                             'SMB 2.???'])
        end
      end
    end
  end
end

