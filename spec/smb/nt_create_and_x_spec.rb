require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB
    pkts = read_packets('smb.pcapng')

    describe NtCreateAndX::Request do
      it 'parses a SMB COM_NT_CREATE_ANDX request packet' do
        pkt = pkts[3]
        expect(pkt.is? 'NetBIOS::Session').to be(true)
        expect(pkt.is? 'SMB').to be(true)
        expect(pkt.smb[:command].to_human).to eq('nt_create_and_x')
        expect(pkt.smb.flags_reply?).to be(false)
        expect(pkt.is? 'SMB::NtCreateAndX::Request').to be(true)
        expect(pkt.smb.body).to be_a(SMB::NtCreateAndX::Request)
        expect(pkt.smb_ntcreateandx_request.word_count).to eq(24)
        expect(pkt.smb_ntcreateandx_request.and_xcommand).to eq(0xff)
        expect(pkt.smb_ntcreateandx_request.rsv1).to eq(0)
        expect(pkt.smb_ntcreateandx_request.and_xoffset).to eq(0)
        expect(pkt.smb_ntcreateandx_request.rsv2).to eq(0)
        expect(pkt.smb_ntcreateandx_request.filename_length).to eq(16)
        expect(pkt.smb_ntcreateandx_request.flags).to eq(0)
        expect(pkt.smb_ntcreateandx_request.root_dir_fid).to eq(0)
        expect(pkt.smb_ntcreateandx_request.access_mask).to eq(0x2019f)
        expect(pkt.smb_ntcreateandx_request.alloc_size).to eq(0)
        expect(pkt.smb_ntcreateandx_request.fattributes).to eq(0)
        expect(pkt.smb_ntcreateandx_request.share_access).to eq(3)
        expect(pkt.smb_ntcreateandx_request.disposition).to eq(1)
        expect(pkt.smb_ntcreateandx_request.options).to eq(0)
        expect(pkt.smb_ntcreateandx_request.impersonation).to eq(2)
        expect(pkt.smb_ntcreateandx_request.sec_flags).to eq(0)
        expect(pkt.smb_ntcreateandx_request.byte_count).to eq(19)
        expect(pkt.smb_ntcreateandx_request.pad1).to eq(0)
        expect(pkt.smb_ntcreateandx_request.filename).to eq('\\srvsvc')
        expect(pkt.smb_ntcreateandx_request[:extra_bytes].sz).to eq(2)
      end

      describe '#calc_length' do
        let(:pkt1) { PacketGen.gen('IP').add('TCP').add('NetBIOS::Session').add('SMB', status: 0xff, flags2: 0x8000).add('SMB::NtCreateAndX::Request', filename: '\\PIPE\\') }
        let(:pkt2) { PacketGen.gen('IP').add('TCP').add('NetBIOS::Session').add('SMB', status: 0xff).add('SMB::NtCreateAndX::Request', filename: '\\PIPE\\') }

        it 'calculates filename length' do
          pkt1.calc
          pkt2.calc
          expect(pkt1.smb_ntcreateandx_request.filename_length).to eq(14)
          expect(pkt2.smb_ntcreateandx_request.filename_length).to eq(7)
        end

        it 'calculates byte count' do
          pkt1.calc
          expect(pkt1.smb_ntcreateandx_request.byte_count).to eq(15)
          pkt1.smb_ntcreateandx_request[:filename].from_human('a')
          pkt1.calc
          expect(pkt1.smb_ntcreateandx_request.byte_count).to eq(5)
          pkt1.smb_ntcreateandx_request.byte_count = 9
          pkt1.smb_ntcreateandx_request[:extra_bytes].read('abcd')
          pkt1.calc
          expect(pkt1.smb_ntcreateandx_request.byte_count).to eq(9)

          pkt2.calc
          expect(pkt2.smb_ntcreateandx_request.byte_count).to eq(7)
          pkt2.smb_ntcreateandx_request[:filename].from_human('a')
          pkt2.calc
          expect(pkt2.smb_ntcreateandx_request.byte_count).to eq(2)
          pkt2.smb_ntcreateandx_request.byte_count = 6
          pkt2.smb_ntcreateandx_request[:extra_bytes].read('abcd')
          pkt2.calc
          expect(pkt2.smb_ntcreateandx_request.byte_count).to eq(6)
        end
      end
    end

    describe NtCreateAndX::Response do
      it 'parses a SMB COM_NT_CREATE_ANDX response packet' do
        pkt = pkts[4]
        expect(pkt.is? 'NetBIOS::Session').to be(true)
        expect(pkt.is? 'SMB').to be(true)
        expect(pkt.smb[:command].to_human).to eq('nt_create_and_x')
        expect(pkt.smb.flags_reply?).to be(true)
        expect(pkt.is? 'SMB::NtCreateAndX::Response').to be(true)
        expect(pkt.smb.body).to be_a(SMB::NtCreateAndX::Response)
        expect(pkt.smb_ntcreateandx_response.word_count).to eq(34)
        expect(pkt.smb_ntcreateandx_response.and_xcommand).to eq(0xff)
        expect(pkt.smb_ntcreateandx_response.and_xoffset).to eq(0)
        expect(pkt.smb_ntcreateandx_response.oplock_level).to eq(0)
        expect(pkt.smb_ntcreateandx_response.fid).to eq(0x762f)
        expect(pkt.smb_ntcreateandx_response.disposition).to eq(1)
        expect(pkt.smb_ntcreateandx_response.create_time.to_i).to eq(0)
        expect(pkt.smb_ntcreateandx_response.access_time.to_i).to eq(0)
        expect(pkt.smb_ntcreateandx_response.write_time.to_i).to eq(0)
        expect(pkt.smb_ntcreateandx_response.change_time.to_i).to eq(0)
        expect(pkt.smb_ntcreateandx_response.fattributes).to eq(0x80)
        expect(pkt.smb_ntcreateandx_response.alloc_size).to eq(0)
        expect(pkt.smb_ntcreateandx_response.end_of_file).to eq(0)
        expect(pkt.smb_ntcreateandx_response.res_type).to eq(2)
        expect(pkt.smb_ntcreateandx_response.pipe_status).to eq(0x05ff)
        expect(pkt.smb_ntcreateandx_response.directory?).to eq(false)
        expect(pkt.smb_ntcreateandx_response.byte_count).to eq(0)
      end
    end
  end
end
