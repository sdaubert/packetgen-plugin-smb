require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB2
    describe GUID do
      it '#to_human' do
        expect(GUID.new.to_human).to eq('00000000-0000-0000-0000-000000000000')

        guid = GUID.new(data1: 0x1234_5678, data2: 0x99aa, data3: 0xbbcc, data4: 0x1234_5678_9abc_def0)
        expect(guid.to_human).to eq('12345678-99aa-bbcc-1234-56789abcdef0')
      end

      it '#from_human' do
        guid = GUID.new
        guid.from_human('12345678-99aa-bbcc-1234-56789abcdef0')
        expect(guid.data1).to eq(0x1234_5678)
        expect(guid.data2).to eq(0x99aa)
        expect(guid.data3).to eq(0xbbcc)
        expect(guid.data4).to eq(0x1234_5678_9abc_def0)
      end
    end
  end
end
