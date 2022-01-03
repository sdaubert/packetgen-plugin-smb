require_relative '../spec_helper'

module PacketGen::Plugin
  class NTLM
    describe Negotiate do
      let(:raw_pkt) { read_raw_packets('smb2.pcapng')[4] }
      let(:raw_str) { PacketGen.parse(raw_pkt).smb2_sessionsetup_request.buffer[:init_env][:token_init][:mech_token].value }

      describe '#read' do
        it 'parses a binary string' do
          nego = Negotiate.new.read(raw_str)
          expect(nego.signature).to eq(SIGNATURE)
          expect(nego.type).to eq(1)
          expect(nego.flags).to eq(0x62088215)
          expect(nego.domain_name_len).to eq(0)
          expect(nego.domain_name_maxlen).to eq(0)
          expect(nego.domain_name_offset).to eq(0x28)
          expect(nego.workstation_len).to eq(0)
          expect(nego.workstation_maxlen).to eq(0)
          expect(nego.workstation_offset).to eq(0x28)
          expect(nego.version).to eq([6, 1, 0, 0, 0, 0, 0, 15].pack('C*'))
          expect(nego.payload).to be_empty
          expect(nego.domain_name).to be_empty
          expect(nego.workstation).to be_empty
        end

        it 'sets domain_name' do
          nego = Negotiate.new
          nego.domain_name = 'DOMAIN'
          nego.calc_length

          nego2 = Negotiate.new.read(nego.to_s)
          expect(nego2.domain_name_len).to eq(6)
          expect(nego2.domain_name_offset).to eq(0x28)
          expect(nego2.payload).to eq('DOMAIN')
          expect(nego2.domain_name).to eq('DOMAIN')
        end

        it 'sets workstation' do
          nego = Negotiate.new
          nego.domain_name = 'DOMAIN'
          nego.workstation = 'PC1'
          nego.calc_length

          nego2 = Negotiate.new.read(nego.to_s)
          expect(nego2.workstation_len).to eq(3)
          expect(nego2.workstation_offset).to eq(0x2e)
          expect(nego2.payload).to eq('DOMAINPC1')
          expect(nego2.workstation).to eq('PC1')
        end
      end

      describe '#calc_length' do
        let(:nego) { Negotiate.new }

        it 'sets domain_name_offset to where it should be (not present)' do
          nego.calc_length
          expect(nego.domain_name_offset).to eq(0x28)
          expect(nego.domain_name_len).to eq(0)
        end

        it 'sets domain_name_offset' do
          nego.domain_name = 'DOMAIN'
          nego.calc_length
          expect(nego.domain_name_offset).to eq(0x28)
        end

        it 'sets domain_name_len' do
          nego.domain_name = 'DOMAIN'
          nego.calc_length
          expect(nego.domain_name_len).to eq(6)
        end

        it 'sets workstation_offset to where it should be (not present)' do
          nego.calc_length
          expect(nego.workstation_offset).to eq(0x28)
          expect(nego.workstation_len).to eq(0)

          nego.domain_name = 'DOMAIN'
          nego.calc_length
          expect(nego.workstation_offset).to eq(0x2e)
          expect(nego.workstation_len).to eq(0)
        end

        it 'sets workstation_offset' do
          nego.workstation = 'PC1'
          nego.calc_length
          expect(nego.workstation_offset).to eq(0x28)

          nego.domain_name = 'DOMAIN'
          nego.calc_length
          expect(nego.workstation_offset).to eq(0x2e)
        end

        it 'sets workstation_len' do
          nego.workstation = 'PC1'
          nego.calc_length
          expect(nego.workstation_len).to eq(3)

          nego.domain_name = 'DOMAIN'
          nego.calc_length
          expect(nego.workstation_len).to eq(3)
        end
      end

      describe '#to_s' do
        let(:nego) { Negotiate.new }

        it 'sets domain_name in #payload' do
          nego.domain_name = 'DOMAIN'
          nego.calc_length
          expect(nego.to_s).to end_with('DOMAIN')
        end

        it 'sets workstation in #payload' do
          nego.workstation = 'WORKSTATION'
          nego.calc_length
          expect(nego.to_s).to end_with('WORKSTATION')
          nego.domain_name = 'DOMAIN'
          nego.calc_length
          expect(nego.to_s).to end_with('DOMAINWORKSTATION')
        end
      end
    end
  end
end
