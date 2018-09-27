require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB
    class Browser
      pkts = read_packets('smb-browser.pcapng')

      describe HostAnnouncement do
        it '#read a header' do
          pkt = pkts.first
          expect(pkt.is?('SMB::Browser')).to be(true)
          expect(pkt.is?('SMB::Browser::HostAnnouncement')).to be(true)
          expect(pkt.smb_browser).to be_a(HostAnnouncement)
          expect(pkt.smb_browser.update_count).to eq(0)
          expect(pkt.smb_browser.periodicity).to eq(12*60*1_000)
          expect(pkt.smb_browser.server_name).to eq(force_binary('DESKTOP-30HMVIQ'))
          expect(pkt.smb_browser.os_ver_maj).to eq(10)
          expect(pkt.smb_browser.os_ver_min).to eq(0)
          expect(pkt.smb_browser.server_type).to eq(0x0000_1003)
          expect(pkt.smb_browser.browser_ver_maj).to eq(15)
          expect(pkt.smb_browser.browser_ver_min).to eq(1)
          expect(pkt.smb_browser.signature).to eq(0xaa55)
          expect(pkt.smb_browser.comment).to eq('')
        end
      end
    end
  end
end
