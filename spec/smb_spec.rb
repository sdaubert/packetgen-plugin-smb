require_relative 'spec_helper'

module PacketGen::Plugin
  pkts = read_packets('smb.pcapng')

  describe SMB do
    describe 'binding' do
      it 'in NetBIOS packets' do
        expect(PacketGen::Header::NetBIOS::Session).to know_header(SMB).with(body: SMB::MARKER)
        expect(SMB).to know_header(SMB::Blocks)
      end
    end

    describe '#initialize' do
      it 'creates a SMB header with default values' do
        smb = SMB.new
        expect(smb.protocol).to eq(SMB::MARKER)
        expect(smb.command).to eq(1)
        expect(smb[:command].to_human).to eq('delete_dir')
        expect(smb.status).to eq(0)
        expect(smb.flags).to eq(0)
        expect(smb.flags2).to eq(0)
        expect(smb.pid_high).to eq(0)
        expect(smb.sec_features).to eq(0)
        expect(smb.reserved).to eq(0)
        expect(smb.tid).to eq(0)
        expect(smb.pid).to eq(0)
        expect(smb.uid).to eq(0)
        expect(smb.mid).to eq(0)
      end
    end

    describe '#read' do
      it 'sets header from a string' do
        smb = SMB.new
        str = (0...smb.sz).to_a.pack('C*')
        smb.read str
        expect(smb.protocol).to eq("\x00\x01\x02\x03")
        expect(smb.command).to eq(4)
        expect(smb.status).to eq(0x08070605)
        expect(smb.flags).to eq(9)
        expect(smb.flags2).to eq(0x0b0a)
        expect(smb.pid_high).to eq(0x0d0c)
        expect(smb.sec_features).to eq(0x1514131211100f0e)
        expect(smb.reserved).to eq(0x1716)
        expect(smb.tid).to eq(0x1918)
        expect(smb.pid).to eq(0x1b1a)
        expect(smb.uid).to eq(0x1d1c)
        expect(smb.mid).to eq(0x1f1e)
      end

      it 'parses a SMB packet' do
        pkt = pkts.first
        expect(pkt.is? 'TCP').to be(true)
        expect(pkt.is? 'NetBIOS::Session').to be(true)
        expect(pkt.is? 'SMB').to be(true)
        expect(pkt.smb.protocol).to eq(SMB::MARKER)
        expect(pkt.smb[:command].to_human).to eq('echo')
        expect(pkt.smb.status).to eq(0)
        expect(pkt.smb.flags).to eq(0x18)
        expect(pkt.smb.flags_reply?).to be(false)
        expect(pkt.smb.flags2).to eq(0xc843)
        expect(pkt.smb.pid_high).to eq(0)
        expect(pkt.smb.sec_features).to eq(0)
        expect(pkt.smb.reserved).to eq(0)
        expect(pkt.smb.tid).to eq(0)
        expect(pkt.smb.pid).to eq(0)
        expect(pkt.smb.uid).to eq(0)
        expect(pkt.smb.mid).to eq(13)
        expect(pkt.smb.body).to be_a(SMB::Blocks)
        expect(pkt.smb_blocks.word_count).to eq(1)
        expect(pkt.smb_blocks.words.map(&:to_i)).to eq([1])
        expect(pkt.smb_blocks.byte_count).to eq(16)
        expect(pkt.smb_blocks.bytes.map(&:to_i)).to eq([0] * 16)

        stri = pkt.smb.inspect
        flags = stri.lines.reject { |l| l !~ /flags:/ }.first.split(':')[1].strip.split(' ').first
        expect(flags).to eq('canon_paths,case_insensitive')
        flags2 = stri.lines.reject { |l| l !~ /flags2:/ }.first.split(':')[1].strip.split(' ').first
        expect(flags2).to eq('unicode,ntstatus,extended_security,is_long_name,eas,long_names')
      end
    end
  end
end
