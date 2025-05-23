require_relative 'spec_helper'

module PacketGen::Plugin
  module NetBIOS
    describe Name do
      let(:name) { Name.new }

      describe '#from_human' do
        it 'encodes a NetBIOS name' do
          name.from_human('The NetBIOS name')
          expect(name.to_s).to eq("\x20FEGIGFCAEOGFHEECEJEPFDCAGOGBGNGF\x00".b)
        end

        it 'encodes a NetBIOS name with a scope ID' do
          name.from_human('FRED.NETBIOS.COM')
          expect(name.to_s).to eq("\x20EGFCEFEECACACACACACACACACACACACA\x07NETBIOS\x03COM\x00".b)
        end
      end

      describe '#to_human' do
        it 'decodes a NetBIOS name' do
          name.read("\x20EGFCEFEECACACACACACACACACACACACA\x07NETBIOS\x03COM\x00".b)
          expect(name.to_human).to eq('FRED')
        end
      end
    end

    describe Session do
      describe 'bindings' do
        it 'in TCP packets with source or destination port 139' do
          expect(PacketGen::Header::TCP).to know_header(Session).with(sport: 139)
          expect(PacketGen::Header::TCP).to know_header(Session).with(dport: 139)
        end
      end
    end

    describe Datagram do
      describe 'bindings' do
        it 'in UDP packets with source and destination ports 138' do
          expect(PacketGen::Header::UDP).to know_header(Datagram).with(sport: 138, dport: 138)
        end
      end

      describe '#calc_length' do
        %w[direct_unique direct_group broadcast].each do |type|
          it "computes DGM length for #{type} datagram" do
            dgm = Datagram.new(type: type)
            body_sz = rand(100)
            dgm.body = '0' * body_sz
            dgm.calc_length
            expect(dgm.dgm_length).to eq(body_sz + 2 * 34)
          end
        end
        %w[query_request positive_query_resp negative_query_resp].each do |type|
          it "computes DGM length for #{type} datagram" do
            dgm = Datagram.new(type: type)
            body_sz = rand(100)
            dgm.body = '0' * body_sz
            dgm.calc_length
            expect(dgm.dgm_length).to eq(body_sz + 34)
          end
        end
      end
    end
  end
end
