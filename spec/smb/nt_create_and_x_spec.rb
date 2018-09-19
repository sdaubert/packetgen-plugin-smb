require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB
    pkts = read_packets('smb.pcapng')

    describe NtCreateAndXRequest do
      it 'parses a SMB COM_NT_CREATE_ANDX request packet' do
        pkt = pkts[3]
        expect(pkt.is? 'NetBIOS::Session').to be(true)
        expect(pkt.is? 'SMB').to be(true)
        expect(pkt.smb[:command].to_human).to eq('nt_create_and_x')
        expect(pkt.smb.flags_reply?).to be(false)
        expect(pkt.is? 'SMB::NtCreateAndXRequest').to be(true)
        expect(pkt.smb.body).to be_a(SMB::NtCreateAndXRequest)
        expect(pkt.smb_ntcreateandxrequest.word_count).to eq(24)
        expect(pkt.smb_ntcreateandxrequest.and_xcommand).to eq(0xff)
        expect(pkt.smb_ntcreateandxrequest.rsv1).to eq(0)
        expect(pkt.smb_ntcreateandxrequest.and_xoffset).to eq(0)
        expect(pkt.smb_ntcreateandxrequest.rsv2).to eq(0)
        expect(pkt.smb_ntcreateandxrequest.filename_length).to eq(16)
        expect(pkt.smb_ntcreateandxrequest.flags).to eq(0)
        expect(pkt.smb_ntcreateandxrequest.root_dir_fid).to eq(0)
        expect(pkt.smb_ntcreateandxrequest.access_mask).to eq(0x2019f)
        expect(pkt.smb_ntcreateandxrequest.alloc_size).to eq(0)
        expect(pkt.smb_ntcreateandxrequest.attributes).to eq(0)
        expect(pkt.smb_ntcreateandxrequest.share_access).to eq(3)
        expect(pkt.smb_ntcreateandxrequest.disposition).to eq(1)
        expect(pkt.smb_ntcreateandxrequest.options).to eq(0)
        expect(pkt.smb_ntcreateandxrequest.impersonation).to eq(2)
        expect(pkt.smb_ntcreateandxrequest.sec_flags).to eq(0)
        expect(pkt.smb_ntcreateandxrequest.byte_count).to eq(19)
        expect(pkt.smb_ntcreateandxrequest.pad1).to eq(0)
        expect(pkt.smb_ntcreateandxrequest.filename).to eq('\\srvsvc'.encode('UTF-16LE'))
        expect(pkt.smb_ntcreateandxrequest.extra_bytes.sz).to eq(2)
      end

      describe '#calc_length' do
        let(:pkt) { PacketGen.gen('IP').add('TCP').add('NetBIOS::Session').add('SMB', status: 0xff).add('SMB::NtCreateAndXRequest', filename: '\\PIPE\\') }

        it 'calculates filename length' do
          pkt.calc
          expect(pkt.smb_ntcreateandxrequest.filename_length).to eq(14)
        end

        it 'calculates byte count' do
          pkt.calc
          expect(pkt.smb_ntcreateandxrequest.byte_count).to eq(15)
          pkt.smb_ntcreateandxrequest[:filename].from_human('a')
          pkt.calc
          expect(pkt.smb_ntcreateandxrequest.byte_count).to eq(5)
          pkt.smb_ntcreateandxrequest.byte_count = 9
          pkt.smb_ntcreateandxrequest[:extra_bytes].read('abcd')
          pkt.calc
          expect(pkt.smb_ntcreateandxrequest.byte_count).to eq(9)
        end
      end
    end

    describe NtCreateAndXResponse do
      it 'parses a SMB COM_NT_CREATE_ANDX response packet' do
        pkt = pkts[4]
        expect(pkt.is? 'NetBIOS::Session').to be(true)
        expect(pkt.is? 'SMB').to be(true)
        expect(pkt.smb[:command].to_human).to eq('nt_create_and_x')
        expect(pkt.smb.flags_reply?).to be(true)
        expect(pkt.is? 'SMB::NtCreateAndXResponse').to be(true)
        expect(pkt.smb.body).to be_a(SMB::NtCreateAndXResponse)
        expect(pkt.smb_ntcreateandxresponse.word_count).to eq(34)
        expect(pkt.smb_ntcreateandxresponse.and_xcommand).to eq(0xff)
        expect(pkt.smb_ntcreateandxresponse.and_xoffset).to eq(0)
        expect(pkt.smb_ntcreateandxresponse.oplock_level).to eq(0)
        expect(pkt.smb_ntcreateandxresponse.fid).to eq(0x762f)
        expect(pkt.smb_ntcreateandxresponse.disposition).to eq(1)
        expect(pkt.smb_ntcreateandxresponse.create_time.to_i).to eq(0)
        expect(pkt.smb_ntcreateandxresponse.access_time.to_i).to eq(0)
        expect(pkt.smb_ntcreateandxresponse.write_time.to_i).to eq(0)
        expect(pkt.smb_ntcreateandxresponse.change_time.to_i).to eq(0)
        expect(pkt.smb_ntcreateandxresponse.attributes).to eq(0x80)
        expect(pkt.smb_ntcreateandxresponse.alloc_size).to eq(0)
        expect(pkt.smb_ntcreateandxresponse.end_of_file).to eq(0)
        expect(pkt.smb_ntcreateandxresponse.res_type).to eq(2)
        expect(pkt.smb_ntcreateandxresponse.pipe_status).to eq(0x05ff)
        expect(pkt.smb_ntcreateandxresponse.directory?).to eq(false)
        expect(pkt.smb_ntcreateandxresponse.byte_count).to eq(0)
      end
    end
  end
end
