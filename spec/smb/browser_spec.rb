require_relative '../spec_helper'

module PacketGen::Plugin
  class SMB
    class Browser
      pkts = read_packets('smb-browser.pcapng')

      describe HostAnnouncement do
        it '#initialize returnd a blank HostAnnouncement' do
          ha = HostAnnouncement.new
          expect(ha.opcode).to eq(1)
          expect(ha.update_count).to eq(0)
          expect(ha.periodicity).to eq(0)
          expect(ha.server_name).to eq(force_binary(''))
          expect(ha.os_ver_maj).to eq(0)
          expect(ha.os_ver_min).to eq(0)
          expect(ha.server_type).to eq(0)
          expect(ha.browser_ver_maj).to eq(15)
          expect(ha.browser_ver_min).to eq(1)
          expect(ha.signature).to eq(0xaa55)
          expect(ha.comment).to eq('')
        end

        it '#read a header' do
          pkt = pkts.first
          expect(pkt.is?('SMB::Browser')).to be(true)
          expect(pkt.is?('SMB::Browser::HostAnnouncement')).to be(true)
          expect(pkt.smb_browser).to be_a(HostAnnouncement)
          expect(pkt.smb_browser.opcode).to eq(1)
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

      describe DomainAnnouncement do
        it '#initialize returnd a blank DomainAnnouncement' do
          ha = DomainAnnouncement.new
          expect(ha.opcode).to eq(12)
        end

        it '#read a header' do
          pkt = pkts[2]
          expect(pkt.is?('SMB::Browser')).to be(true)
          expect(pkt.is?('SMB::Browser::DomainAnnouncement')).to be(true)
          expect(pkt.smb_browser).to be_a(DomainAnnouncement)
          expect(pkt.smb_browser.opcode).to eq(12)
          expect(pkt.smb_browser.update_count).to eq(71)
          expect(pkt.smb_browser.periodicity).to eq(12*60*1_000)
          expect(pkt.smb_browser.machine_group).to eq(force_binary('WORKGROUP'))
          expect(pkt.smb_browser.browser_conf_ver_maj).to eq(4)
          expect(pkt.smb_browser.browser_conf_ver_min).to eq(9)
          expect(pkt.smb_browser.server_type).to eq(0x8000_1000)
          expect(pkt.smb_browser.browser_ver_maj).to eq(15)
          expect(pkt.smb_browser.browser_ver_min).to eq(1)
          expect(pkt.smb_browser.signature).to eq(0xaa55)
          expect(pkt.smb_browser.local_master_name).to eq('FREEBOX')
        end
      end

      describe LocalMasterAnnouncement do
        it '#initialize returnd a blank LocalMasterAnnouncement' do
          ha = LocalMasterAnnouncement.new
          expect(ha.opcode).to eq(15)
        end

        it '#read a header' do
          pkt = pkts[1]
          expect(pkt.is?('SMB::Browser')).to be(true)
          expect(pkt.is?('SMB::Browser::LocalMasterAnnouncement')).to be(true)
          expect(pkt.smb_browser).to be_a(LocalMasterAnnouncement)
          expect(pkt.smb_browser.opcode).to eq(15)
          expect(pkt.smb_browser.update_count).to eq(71)
          expect(pkt.smb_browser.periodicity).to eq(12*60*1_000)
          expect(pkt.smb_browser.server_name).to eq(force_binary('FREEBOX'))
          expect(pkt.smb_browser.os_ver_maj).to eq(4)
          expect(pkt.smb_browser.os_ver_min).to eq(9)
          expect(pkt.smb_browser.server_type).to eq(0x0084_9a03)
          expect(pkt.smb_browser.browser_ver_maj).to eq(15)
          expect(pkt.smb_browser.browser_ver_min).to eq(1)
          expect(pkt.smb_browser.signature).to eq(0xaa55)
          expect(pkt.smb_browser.comment).to eq('Freebox Server')
        end
      end
    end
  end
end
