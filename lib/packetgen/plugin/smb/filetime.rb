# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class SMB
    # 64-bit signed integer, little endian representation
    # @author Sylvain Daubert
    class SInt64le < PacketGen::Types::Int64le
      def initialize(value=nil)
        super
        @packstr[:little] = 'q<'
      end
    end

    # SMB FILETIME.
    # @author Sylvain Daubert
    class Filetime
      # Base time for SMB FILETIME.
      # This value also indicate no time.
      NO_TIME = Time.utc(1601).freeze

      # @param [Hash] options
      # @option options [Integer] :filetime
      # @option options [Time] :time
      # @raise [ArgumentError] if +:time+ and +:filetime+ are both given.
      def initialize(options={})
        if (options.keys & %i[time filetime]).size == 2
          raise ArgumentError, ':time and :filetime options are both given'
        end

        @int = SInt64le.new(options[:filetime])
        if options[:time]
          @time = options[:time]
          @int.value = time2filetime
        else
          @time = filetime2time
        end
      end

      # @param [::String] str
      # @return [String] self
      def read(str)
        @int.read(str[0, 8])
        @time = filetime2time
        self
      end

      # Human readable filetime
      # @return [String]
      def to_human
        if no_time?
          'no time'
        else
          @time.to_s
        end
      end

      # Get filetime integer value
      # @return [Integer]
      def to_i
        @int.to_i
      end

      # Check if there is no time specified
      # @return [Boolean]
      def no_time?
        to_i == 0
      end

      # @return [Integer]
      def sz
        @int.sz
      end

      # @return [String]
      def to_s
        @int.to_s
      end

      # @return [Time]
      def to_time
        @time
      end

      private

      def filetime2time
        filetime = @int.to_i
        secs = filetime / 10_000
        nsecs = (filetime % 10_000) * 100
        if filetime.zero?
          NO_TIME
        elsif filetime.positive?
          Time.at(NO_TIME) + Rational("#{secs}.%09d" % nsecs)
        else
          Time.at(Time.now.utc) + Rational("#{secs}.%09d" % nsecs)
        end
      end

      def time2filetime
        # Time#to_f then #to_r is more precise than Time#to_r
        # (ie Time#to_r sometimes does a rounding error).
        (@time.to_i - NO_TIME.to_i) * 10_000 + ((@time.to_f.to_r * 10_000) % 10_000).to_i
      end
    end
  end
end
