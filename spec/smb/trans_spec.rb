require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB
    pkts = read_packets('smb.pcapng')

    describe TransRequest do
      it 'parses a SMB COM_TRANSACTION request packet' do
        pkt = pkts[5]
        expect(pkt.is? 'NetBIOS::Session').to be(true)
        expect(pkt.is? 'SMB').to be(true)
        expect(pkt.smb[:command].to_human).to eq('trans')
        expect(pkt.smb.flags_reply?).to be(false)
        expect(pkt.is? 'SMB::TransRequest').to be(true)
        expect(pkt.smb.body).to be_a(SMB::TransRequest)
        expect(pkt.smb_transrequest.word_count).to eq(16)
        expect(pkt.smb_transrequest.total_param_count).to eq(0)
        expect(pkt.smb_transrequest.total_data_count).to eq(72)
        expect(pkt.smb_transrequest.max_param_count).to eq(0)
        expect(pkt.smb_transrequest.max_data_count).to eq(4280)
        expect(pkt.smb_transrequest.max_setup_count).to eq(0)
        expect(pkt.smb_transrequest.rsv1).to eq(0)
        expect(pkt.smb_transrequest.flags).to eq(0)
        expect(pkt.smb_transrequest.timeout).to eq(0)
        expect(pkt.smb_transrequest.rsv2).to eq(0)
        expect(pkt.smb_transrequest.param_count).to eq(0)
        expect(pkt.smb_transrequest.param_offset).to eq(84)
        expect(pkt.smb_transrequest.data_count).to eq(72)
        expect(pkt.smb_transrequest.data_offset).to eq(84)
        expect(pkt.smb_transrequest.setup_count).to eq(2)
        expect(pkt.smb_transrequest.setup.map(&:to_i)).to eq([38, 30_255])
        expect(pkt.smb_transrequest.byte_count).to eq(89)
        expect(pkt.smb_transrequest.name).to eq("\\PIPE\\".encode('UTF-16LE'))
        expect(pkt.smb_transrequest.pad1.size).to eq(2)
      end
    end

    describe TransResponse do
      it 'parses a SMB COM_TRANSACTION response packet' do
        pkt = pkts[6]
        expect(pkt.is? 'NetBIOS::Session').to be(true)
        expect(pkt.is? 'SMB').to be(true)
        expect(pkt.smb[:command].to_human).to eq('trans')
        expect(pkt.smb.flags_reply?).to be(true)
        expect(pkt.is? 'SMB::TransResponse').to be(true)
        expect(pkt.smb.body).to be_a(SMB::TransResponse)
        expect(pkt.smb_transresponse.word_count).to eq(10)
        expect(pkt.smb_transresponse.total_param_count).to eq(0)
        expect(pkt.smb_transresponse.total_data_count).to eq(68)
        expect(pkt.smb_transresponse.rsv1).to eq(0)
        expect(pkt.smb_transresponse.param_count).to eq(0)
        expect(pkt.smb_transresponse.param_offset).to eq(56)
        expect(pkt.smb_transresponse.param_displacement).to eq(0)
        expect(pkt.smb_transresponse.data_count).to eq(68)
        expect(pkt.smb_transresponse.data_offset).to eq(56)
        expect(pkt.smb_transresponse.data_displacement).to eq(0)
        expect(pkt.smb_transresponse.setup_count).to eq(0)
        expect(pkt.smb_transresponse.rsv2).to eq(0)
        expect(pkt.smb_transresponse.setup.empty?).to be(true)
        expect(pkt.smb_transresponse.byte_count).to eq(69)
        expect(pkt.smb_transresponse.pad1.size).to eq(1)
      end
    end
  end
end
