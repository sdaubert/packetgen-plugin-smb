require_relative 'spec_helper'

SMB2_EMPTY_SIG = ("\0" * 16).freeze

module PacketGen::Plugin
  pkts = read_packets('smb2.pcapng')
  describe SMB2 do
    describe 'binding' do
      it 'in NetBIOS packets' do
        expect(NetBIOS::Session).to know_header(SMB2).with(body: SMB2::MARKER)
      end
    end

    describe '#initialize' do
      it 'creates a SMB2 header with default values' do
        smb = SMB2.new
        expect(smb.protocol).to eq(SMB2::MARKER)
        expect(smb.structure_size).to eq(64)
        expect(smb.credit_charge).to eq(0)
        expect(smb.status).to eq(0)
        expect(smb.command).to eq(0)
        expect(smb[:command].to_human).to eq('negotiate')
        expect(smb.credit).to eq(0)
        expect(smb.flags).to eq(0)
        expect(smb.next_command).to eq(0)
        expect(smb.message_id).to eq(0)
        expect(smb.present?(:async_id)).to be(false)
        expect(smb.present?(:reserved)).to be(true)
        expect(smb.reserved).to eq(0)
        expect(smb.present?(:tree_id)).to be(true)
        expect(smb.tree_id).to eq(0)
        expect(smb.session_id).to eq(0)
        expect(smb.signature).to eq(SMB2_EMPTY_SIG)
      end
    end

    describe '#read' do
      it 'sets header from a string' do
        smb = SMB2.new
        str = (0...smb.sz).to_a.pack('C*')
        smb.read str
        expect(smb.protocol).to eq("\x00\x01\x02\x03")
        expect(smb.structure_size).to eq(0x0504)
        expect(smb.credit_charge).to eq(0x0706)
        expect(smb.status).to eq(0x0b0a0908)
        expect(smb.command).to eq(0x0d0c)
        expect(smb.credit).to eq(0x0f0e)
        expect(smb.flags).to eq(0x13121110)
        expect(smb.next_command).to eq(0x17161514)
        expect(smb.message_id).to eq(0x1f1e1d1c1b1a1918)
        expect(smb.reserved).to eq(0x23222120)
        expect(smb.tree_id).to eq(0x27262524)
        expect(smb.session_id).to eq(0x2f2e2d2c2b2a2928)
        expect(smb.signature).to eq((0x30...0x40).to_a.pack('C*'))
      end

      it 'parses a SMB2 packet' do
        pkt = pkts[2]
        expect(pkt.is? 'TCP').to be(true)
        expect(pkt.tcp.dport).to eq(445)
        expect(pkt.is? 'NetBIOS::Session').to be(true)
        expect(pkt.is? 'SMB2').to be(true)
        expect(pkt.smb2.protocol).to eq(SMB2::MARKER)
        expect(pkt.smb2.structure_size).to eq(64)
        expect(pkt.smb2.credit_charge).to eq(0)
        expect(pkt.smb2.status).to eq(0)
        expect(pkt.smb2[:command].to_human).to eq('negotiate')
        expect(pkt.smb2.credit).to eq(31)
        expect(pkt.smb2.flags).to eq(0)
        expect(pkt.smb2.flags_response?).to be(false)
        expect(pkt.smb2.next_command).to eq(0)
        expect(pkt.smb2.message_id).to eq(1)
        expect(pkt.smb2.reserved).to eq(0)
        expect(pkt.smb2.tree_id).to eq(0)
        expect(pkt.smb2.session_id).to eq(0)
        expect(pkt.smb2.signature).to eq(SMB2_EMPTY_SIG)

        pkt = pkts[15]
        expect(pkt.is? 'SMB2').to be(true)
        expect(pkt.smb2.protocol).to eq(SMB2::MARKER)
        expect(pkt.smb2.structure_size).to eq(64)
        expect(pkt.smb2.credit_charge).to eq(1)
        expect(pkt.smb2.status).to eq(0)
        expect(pkt.smb2[:command].to_human).to eq('tree_connect')
        expect(pkt.smb2.credit).to eq(1)
        expect(pkt.smb2.flags).to eq(0x19)
        expect(pkt.smb2.flags_response?).to be(true)
        expect(pkt.smb2.flags_signed?).to be(true)
        expect(pkt.smb2.flags_smb3_priority).to eq(1)
        expect(pkt.smb2.next_command).to eq(0)
        expect(pkt.smb2.message_id).to eq(7)
        expect(pkt.smb2.reserved).to eq(0)
        expect(pkt.smb2.tree_id).to eq(5)
        expect(pkt.smb2.session_id).to eq(0x840000000049)
        sig = force_binary("\xa9\xa6\xd1\xa8\x0d\x7d\x0a\xba\x11\xd2\xcd\x79\x90\x7f\xe6\x86")
        expect(pkt.smb2.signature).to eq(sig)
      end
    end

    describe '#inspect' do
      let(:smb2) { SMB2.new }

      it 'puts a line for each attribute but body' do
        str = smb2.inspect
        (smb2.attributes - %i[body async_id]).each do |field|
          expect(str).to include(field.to_s)
        end

        smb2 = SMB2.new(flags_async: true)
        str = smb2.inspect
        (smb2.attributes - %i[body reserved tree_id]).each do |field|
          expect(str).to include(field.to_s)
        end
      end

      it 'processes flags field as a set of flags' do
        smb2.flags = 0xffff_ffff
        str = smb2.inspect.split("\n").find { |l| l =~ /flags/ }
        expect(str).to include('smb3_replay_op,dfs_op,signed,related_op,async,response')
      end
    end
  end
end
