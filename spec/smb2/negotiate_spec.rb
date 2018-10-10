require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB2
    pkts = read_packets('smb2.pcapng')

    describe Negotiate::Request do
      it 'parses a SMB2 Neogiate request packet' do
        pkt = pkts[2]
        expect(pkt.is?('SMB2')).to be(true)
        expect(pkt.smb2.command).to eq(0)
        expect(pkt.smb2[:command].to_human).to eq('negotiate')
        expect(pkt.smb2.flags_response?).to be(false)
        expect(pkt.is?('SMB2::Negotiate::Request')).to be(true)
        nego = pkt.smb2_negotiate_request
        expect(nego.structure_size).to eq(36)
        expect(nego.dialect_count).to eq(8)
        expect(nego.security_mode).to eq(1)
        expect(nego[:security_mode].to_human).to eq('signing_enabled')
        expect(nego.reserved).to eq(0)
        expect(nego.capabilities).to eq(0x7f)
        nego.bits_on(:capabilities).each do |k, v|
          next if v > 1
          expect(nego.send("#{k}?")).to be(true)
        end
        expect(nego.client_guid).to eq('7aedb437-01b9-41d4-a5f7-9e6c06e16c8a')
        expect(nego.context_offset).to eq(0x78)
        expect(nego.context_count).to eq(2)
        expect(nego.reserved2).to eq(0)
        expect(nego.dialects.map(&:to_i)).to eq([0x202, 0x210, 0x222, 0x224, 0x300, 0x302, 0x310, 0x311])
        expect(nego.pad.size).to eq(4)
        expect(nego.context_list.size).to eq(2)

        context = nego.context_list[0]
        expect(context.human_type).to eq('PREAUTH_INTEGRITY_CAP')
        expect(context.data_length).to eq(38)
        p context

        context = nego.context_list[1]
        expect(context.human_type).to eq('ENCRYPTION_CAP')
        expect(context.data_length).to eq(6)
        p context
      end
    end

    describe Negotiate::Response do
      it 'parses a SMB2 Neogiate response packet' do
        pkt = pkts[3]
        expect(pkt.is?('SMB2')).to be(true)
        expect(pkt.smb2.command).to eq(0)
        expect(pkt.smb2[:command].to_human).to eq('negotiate')
        expect(pkt.smb2.flags_response?).to be(true)
        expect(pkt.is?('SMB2::Negotiate::Response')).to be(true)
        nego = pkt.smb2_negotiate_response
        expect(nego.structure_size).to eq(65)
        expect(nego.security_mode).to eq(1)
        expect(nego.dialect).to eq(0x311)
        expect(nego.context_count).to eq(2)
        expect(nego.server_guid).to eq('f9a55f79-6266-4a4c-86bc-989430e8d43f')
        expect(nego.capabilities).to eq(0x2f)
        expect(nego.cap_encryption?).to be(false)
        expect(nego.cap_dir_leasing?).to be(true)
        expect(nego.cap_persistent_handles?).to be(false)
        expect(nego.cap_multi_channel?).to be(true)
        expect(nego.cap_large_mtu?).to be(true)
        expect(nego.cap_leasing?).to be(true)
        expect(nego.cap_dfs?).to be(true)
        expect(nego.max_trans_size).to eq(0x800000)
        expect(nego.max_read_size).to eq(0x800000)
        expect(nego.max_write_size).to eq(0x800000)
        expect(nego.system_time.to_human).to eq('2018-10-04 18:13:04.463807700 UTC')
        expect(nego.start_time.to_human).to eq('no time')
        expect(nego.buffer_offset).to eq(0x80)
        expect(nego.buffer_length).to eq(320)
        expect(nego.context_offset).to eq(0x1c0)
        expect(nego.buffer.size).to eq(320)
        expect(nego.pad.size).to eq(0)
        expect(nego.context_list.size).to eq(2)

        context = nego.context_list[0]
        expect(context.human_type).to eq('PREAUTH_INTEGRITY_CAP')
        expect(context.data_length).to eq(38)

        context = nego.context_list[1]
        expect(context.human_type).to eq('ENCRYPTION_CAP')
        expect(context.data_length).to eq(4)
      end
    end
  end
end
