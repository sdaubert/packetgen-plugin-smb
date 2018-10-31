require_relative 'spec_helper'

module PacketGen::Plugin
  describe LLMNR do
    describe '#read' do
      let(:raw_pkts) { read_raw_packets('smb2-nego.pcapng')[2..3] }

      it 'parses a LLMNR request header' do
        pkt = PacketGen.parse(raw_pkts[0])
        expect(pkt.is?('UDP')).to be(true)
        expect(pkt.udp.dport).to eq(LLMNR::UDP_PORT)
        expect(pkt.is?('LLMNR')).to be(true)
        expect(pkt.llmnr.id).to eq(0x5cc6)
        expect(pkt.llmnr.u16).to eq(0)
        expect(pkt.llmnr.query?).to be(true)
        expect(pkt.llmnr.qdcount).to eq(1)
        expect(pkt.llmnr.ancount).to eq(0)
        expect(pkt.llmnr.nscount).to eq(0)
        expect(pkt.llmnr.arcount).to eq(0)

        question = pkt.llmnr.qd[0]
        expect(question.name).to eq('testshare2.')
        expect(question.rrclass).to eq(1)
        expect(question.type).to eq(1)
      end

      it 'parses a LLMNR response header' do
        pkt = PacketGen.parse(raw_pkts[1])
        expect(pkt.is?('UDP')).to be(true)
        expect(pkt.udp.sport).to eq(LLMNR::UDP_PORT)
        expect(pkt.is?('LLMNR')).to be(true)
        expect(pkt.llmnr.id).to eq(0x5cc6)
        expect(pkt.llmnr.u16).to eq(0x8000)
        expect(pkt.llmnr.response?).to be(true)
        expect(pkt.llmnr.qdcount).to eq(1)
        expect(pkt.llmnr.ancount).to eq(1)
        expect(pkt.llmnr.nscount).to eq(0)
        expect(pkt.llmnr.arcount).to eq(0)

        question = pkt.llmnr.qd[0]
        expect(question.name).to eq('testshare2.')
        expect(question.rrclass).to eq(1)
        expect(question.type).to eq(1)

        answer = pkt.llmnr.an[0]
        expect(answer.name).to eq('testshare2.')
        expect(answer.rrclass).to eq(1)
        expect(answer.type).to eq(1)
        expect(answer.ttl).to eq(30)
        expect(answer.rdlength).to eq(4)
        expect(answer.human_rdata).to eq('192.168.0.84')
      end
    end

    describe '#llmnrize' do
      let(:pkt) { PacketGen.gen('Eth').add('IP').add('UDP').add('LLMNR') }
      let(:pkt2) { PacketGen.gen('Dot11::Data').add('LLC').add('SNAP').add('IP').add('UDP').add('LLMNR') }

      it 'sets given IP destination address' do
        pkt.llmnrize(dst: '192.168.1.1')
        expect(pkt.ip.dst).to eq('192.168.1.1')
      end

      it 'sets TTL to 1 if given IP address is a multicast one' do
        pkt.llmnrize(dst: '224.0.0.252')
        expect(pkt.ip.dst).to eq('224.0.0.252')
        expect(pkt.ip.ttl).to eq(1)
      end

      it 'sets destination mac address if given IP address is a multicast one' do
        pkt.llmnrize(dst: '224.0.0.252')
        expect(pkt.eth.dst).to eq(LLMNR::MAC_IPV4_MCAST)
        pkt2.llmnrize(dst: '224.0.0.252')
        expect(pkt2.dot11.dst).to eq(LLMNR::MAC_IPV4_MCAST)
      end

      it 'does not raise if given IP address is a multicast one and there is no LL header' do
        pkt.decapsulate(pkt.eth)
        expect { pkt.llmnrize(dst: '224.0.0.252') }.to_not raise_error
        expect(pkt.ip.dst).to eq('224.0.0.252')
      end
    end
  end
end
