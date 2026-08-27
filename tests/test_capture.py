import unittest
from nemos.capture import PacketCapture

class Layer:
    def __init__(self, **kw): self.__dict__.update(kw)

class FakePacket:
    def __init__(self,layers): self.layers=layers
    def haslayer(self, typ): return typ in self.layers
    def __getitem__(self, typ): return self.layers[typ]
    def __len__(self): return 100

class CaptureTests(unittest.TestCase):
    def setUp(self):
        class IP: pass
        class TCP: pass
        class UDP: pass
        class ICMP: pass
        class DNS: pass
        self.IP,self.TCP,self.UDP,self.ICMP,self.DNS=IP,TCP,UDP,ICMP,DNS
    def test_status_before_start(self):
        capture = PacketCapture(None, lambda *_: None)
        status = capture.status()
        self.assertEqual(status["state"], "stopped")
        self.assertFalse(status["running"])
        self.assertEqual(status["packets_seen"], 0)

    def test_tcp_parse(self):
        p=FakePacket({self.IP:Layer(src="10.0.0.1",dst="10.0.0.2"),self.TCP:Layer(sport=1234,dport=443,flags="S")})
        e,kind=PacketCapture._parse(p,self.IP,self.TCP,self.UDP,self.ICMP,self.DNS)
        self.assertEqual(kind,"TCP");self.assertEqual(e.destination_port,443);self.assertEqual(e.flags,"S")
    def test_dns_parse(self):
        p=FakePacket({self.IP:Layer(src="10.0.0.1",dst="8.8.8.8"),self.UDP:Layer(sport=1234,dport=53),self.DNS:Layer()})
        e,kind=PacketCapture._parse(p,self.IP,self.TCP,self.UDP,self.ICMP,self.DNS)
        self.assertEqual(kind,"DNS");self.assertEqual(e.protocol,"DNS")
if __name__ == "__main__":
    unittest.main()
