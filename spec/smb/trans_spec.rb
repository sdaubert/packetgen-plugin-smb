require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB
    pkts = read_packets('smb.pcapng')

    describe Trans::Request do
      it 'parses a SMB COM_TRANSACTION request packet' do
        pkt = pkts[5]
        expect(pkt.is? 'NetBIOS::Session').to be(true)
        expect(pkt.is? 'SMB').to be(true)
        expect(pkt.smb[:command].to_human).to eq('trans')
        expect(pkt.smb.flags_reply?).to be(false)
        expect(pkt.is? 'SMB::Trans::Request').to be(true)
        expect(pkt.smb.body).to be_a(SMB::Trans::Request)
        expect(pkt.smb_trans_request.word_count).to eq(16)
        expect(pkt.smb_trans_request.total_param_count).to eq(0)
        expect(pkt.smb_trans_request.total_data_count).to eq(72)
        expect(pkt.smb_trans_request.max_param_count).to eq(0)
        expect(pkt.smb_trans_request.max_data_count).to eq(4280)
        expect(pkt.smb_trans_request.max_setup_count).to eq(0)
        expect(pkt.smb_trans_request.rsv1).to eq(0)
        expect(pkt.smb_trans_request.flags).to eq(0)
        expect(pkt.smb_trans_request.timeout).to eq(0)
        expect(pkt.smb_trans_request.rsv2).to eq(0)
        expect(pkt.smb_trans_request.param_count).to eq(0)
        expect(pkt.smb_trans_request.param_offset).to eq(84)
        expect(pkt.smb_trans_request.data_count).to eq(72)
        expect(pkt.smb_trans_request.data_offset).to eq(84)
        expect(pkt.smb_trans_request.setup_count).to eq(2)
        expect(pkt.smb_trans_request.setup.map(&:to_i)).to eq([38, 30_255])
        expect(pkt.smb_trans_request.byte_count).to eq(89)
        expect(pkt.smb_trans_request.name).to eq("\\PIPE\\")
        expect(pkt.smb_trans_request.pad1.size).to eq(2)
      end
    end

    describe Trans::Response do
      it 'parses a SMB COM_TRANSACTION response packet' do
        pkt = pkts[6]
        expect(pkt.is? 'NetBIOS::Session').to be(true)
        expect(pkt.is? 'SMB').to be(true)
        expect(pkt.smb[:command].to_human).to eq('trans')
        expect(pkt.smb.flags_reply?).to be(true)
        expect(pkt.is? 'SMB::Trans::Response').to be(true)
        expect(pkt.smb.body).to be_a(SMB::Trans::Response)
        expect(pkt.smb_trans_response.word_count).to eq(10)
        expect(pkt.smb_trans_response.total_param_count).to eq(0)
        expect(pkt.smb_trans_response.total_data_count).to eq(68)
        expect(pkt.smb_trans_response.rsv1).to eq(0)
        expect(pkt.smb_trans_response.param_count).to eq(0)
        expect(pkt.smb_trans_response.param_offset).to eq(56)
        expect(pkt.smb_trans_response.param_displacement).to eq(0)
        expect(pkt.smb_trans_response.data_count).to eq(68)
        expect(pkt.smb_trans_response.data_offset).to eq(56)
        expect(pkt.smb_trans_response.data_displacement).to eq(0)
        expect(pkt.smb_trans_response.setup_count).to eq(0)
        expect(pkt.smb_trans_response.rsv2).to eq(0)
        expect(pkt.smb_trans_response.setup.empty?).to be(true)
        expect(pkt.smb_trans_response.byte_count).to eq(69)
        expect(pkt.smb_trans_response.pad1.size).to eq(1)
      end
    end
  end
end
