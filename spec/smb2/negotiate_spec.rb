require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB2
    pkts = read_packets('smb2.pcapng')

    describe Negotiate::Request do
      it 'parses a SMB2 Negotiate request packet' do
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
        expect(context).to be_a(Negotiate::PreauthIntegrityCap)
        expect(context.human_type).to eq('PREAUTH_INTEGRITY_CAP')
        expect(context.data_length).to eq(38)
        expect(context.reserved).to eq(0)
        expect(context.hash_alg_count).to eq(1)
        expect(context.salt_length).to eq(32)
        expect(context.hash_alg.size).to eq(1)
        expect(context.hash_alg.map(&:to_i)).to eq([1])
        expect(context.salt[0, 4]).to eq(force_binary("\xd5\xec\x0d\x5e"))
        expect(context.pad.size).to eq(2)

        context = nego.context_list[1]
        expect(context).to be_a(Negotiate::EncryptionCap)
        expect(context.human_type).to eq('ENCRYPTION_CAP')
        expect(context.data_length).to eq(6)
        expect(context.reserved).to eq(0)
        expect(context.cipher_count).to eq(2)
        expect(context.ciphers.size).to eq(2)
        expect(context.ciphers.map(&:to_i)).to eq([1, 2])
        expect(context.pad.size).to eq(0)
      end

      describe '#calc_length' do
        let(:nr) { Negotiate::Request.new }

        it 'sets context_offset field' do
          nr.calc_length
          expect(nr.context_offset).to eq(0)

          nr.context_list << { type: 2 }
          nr.calc_length
          expect(nr.context_offset).to eq(104)
        end

        it 'sets pad field' do
          nr[:buffer] = PacketGen::Types::String.new
          6.times do |i|
            nr[:dialects] << PacketGen::Types::Int16le.new(i) unless i == 0
            nr.calc_length
            expect(nr.pad.size).to eq((4 - i * 2) % 8)
          end
        end

        it 'sets length for each context' do
          nr.context_list << { type: 1 }
          nr.context_list << { type: 2 }
          nr.calc_length

          expect(nr.context_list[0].data_length).to eq(4)
          expect(nr.context_list[1].data_length).to eq(2)
        end
      end
    end

    describe Negotiate::Response do
      it 'parses a SMB2 Negotiate response packet' do
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
        expect(nego.system_time).to eq('2018-10-04 18:13:04.463807700 UTC')
        expect(nego.start_time).to eq('no time')
        expect(nego.buffer_offset).to eq(0x80)
        expect(nego.buffer_length).to eq(320)
        expect(nego.context_offset).to eq(0x1c0)
        expect(nego.buffer.sz).to eq(320)
        expect(nego.pad.size).to eq(0)
        expect(nego.context_list.size).to eq(2)

        context = nego.context_list[0]
        expect(context.human_type).to eq('PREAUTH_INTEGRITY_CAP')
        expect(context.data_length).to eq(38)

        context = nego.context_list[1]
        expect(context.human_type).to eq('ENCRYPTION_CAP')
        expect(context.data_length).to eq(4)
      end

      describe '#inspect' do
        it 'process capabilities differently' do
          nr = Negotiate::Response.new
          nr.capabilities = 127
          str = nr.inspect.split("\n").find { |l| l =~ /capabilities/ }
          expect(str).to include('encryption,dir_leasing,persistent_handles,multi_channel,large_mtu,leasing,dfs')
        end
      end

      describe '#calc_length' do
        let(:nr) { Negotiate::Response.new }

        it 'sets context_offset field' do
          nr.calc_length
          expect(nr.context_offset).to eq(0)

          nr.context_list << { type: 2 }
          nr.calc_length
          expect(nr.context_offset).to eq(136)
        end

        it 'sets buffer_offset field' do
          nr.calc_length
          expect(nr.buffer_offset).to eq(128)
        end

        it 'sets buffer_length field' do
          nr[:buffer] = PacketGen::Types::String.new
          nr[:buffer].read 'abcdef'
          nr.calc_length
          expect(nr.buffer_length).to eq(6)
        end

        it 'sets pad field' do
          nr[:buffer] = PacketGen::Types::String.new
          12.times do |i|
            nr[:buffer].read('a' * i)
            nr.calc_length
            expect(nr.pad.size).to eq((8 - i) % 8)
          end
        end

        it 'sets length for each context' do
          nr.context_list << { type: 1 }
          nr.context_list << { type: 2 }
          nr.calc_length

          expect(nr.context_list[0].data_length).to eq(4)
          expect(nr.context_list[1].data_length).to eq(2)
        end
      end
    end

    describe Negotiate::Context do
      it '#to_human returns human-readable type' do
        ctx = Negotiate::Context.new(type: 2)
        expect(ctx.to_human).to eq('ENCRYPTION_CAP')
      end

      it '#calc_length compute length of data part' do
        ctx = Negotiate::Context.new
        ctx[:data].replace 'abcd'
        ctx.calc_length
        expect(ctx.data_length).to eq(4)

        ctx = Negotiate::PreauthIntegrityCap.new
        ctx.hash_alg << PacketGen::Types::Int16le.new(1)
        ctx.calc_length
        expect(ctx.data_length).to eq(6)
      end
    end

    describe Negotiate::ArrayOfContext do
      let(:ary) { Negotiate::ArrayOfContext.new }

      it '#<< accepts a hash describing a Context' do
        ary << { type: 42, data_length: 4, data: 'abcd' }
        expect(ary.first).to be_a(Negotiate::Context)
        expect(ary.first.type).to eq(42)
        expect(ary.first.data_length).to eq(4)
        expect(ary.first.data).to eq('abcd')
      end

      it '#<< infers known Context subclasses from hash' do
        ary << { type: 1, salt_length: 4, salt: 'abcd' }
        expect(ary.last).to be_a(Negotiate::PreauthIntegrityCap)
        expect(ary.last.salt_length).to eq(4)
        expect(ary.last.salt).to eq('abcd')

        ary << { type: 2 }
        expect(ary.last).to be_a(Negotiate::EncryptionCap)
      end
    end
  end
end
