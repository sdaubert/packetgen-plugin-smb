require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB
    describe Filetime do
      describe '#initialize' do
        let(:ft) { Filetime.new }
        it 'initializes to integer value 0' do
          expect(ft.to_i).to eq(0)
        end

        it 'initializes to no time' do
          expect(ft.to_human).to eq('no time')
          expect(ft.to_time).to eq(Filetime::NO_TIME)
        end

        it 'accepts a time parameter' do
          ft = nil
          time = Time.new(2018, 9, 14, 0, 0, 0.144)
          expect { ft = Filetime.new(time: time) }.to_not raise_error
          expect(ft.to_time).to eq(time)
          expect(ft.to_i).to eq(131_813_501_611_440)
        end

        it 'accepts a filetime parameter' do
          ft = nil
          ftime = 365 * 3_600 * 24 * 10_000
          expect { ft = Filetime.new(filetime: ftime) }.to_not raise_error
          expect(ft.to_time).to eq(Time.new(1602))
        end

        it 'accepts a negative filetime parameter' do
          ft = nil
          # relative time: 1 min before now
          ftime = -60 * 10_000
          expect { ft = Filetime.new(filetime: ftime) }.to_not raise_error
          expect(ft.to_time).to be_within(1).of(Time.now - 60)
        end

        it 'raises when both time and filetime parameters are given' do
          t = Time.now
          expect { Filetime.new(filetime: 0, time: Time) }.to raise_error(ArgumentError)
        end
      end

      describe '#to_s' do
        it 'returns a binary string with filetime encoded as an Int64le' do
          time1 = Time.new(2018, 9, 14, 15, 04, 14)
          time2 = Time.at(time1.to_i, 229239243, :nsec)
          ft = Filetime.new(time: time2)
          expect(ft.to_s).to eq(force_binary("\xe4\x31\x47\x59\xe2\x77\x00\x00"))
        end
      end

      describe '#to_human' do
        it 'returns a human readable time' do
          ft = Filetime.new(time: Time.new(2018, 9, 15, 15, 33, 27))
          expect(ft.to_human).to match(/^2018-09-15 15:33:27 (?:\+\d{4}|UTC)/)
        end
      end
    end
  end
end