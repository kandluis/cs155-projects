import re
import unittest
import ast
import os

from collections import defaultdict
from collections import Counter


def CHECK(value, assertion):
  if not assertion():
    print(value)
    assert False


class IPAddress(object):
  def __init__(self, raw_ip):
    '''
    raw_ip is of the form N.N.N.N.PORT
    '''
    self.raw = raw_ip
    values = raw_ip.split(".")
    if not (len(values) == 4 or len(values) == 5):
      raise ValueError('IP address is in wrong format!')
    self.port = None
    if (len(values) == 5):
      self.port = values[-1]
      values.pop()

    CHECK(values, lambda: len(values) == 4)
    self.ip_values = list(map(int, values))
    self.ip = ".".join(values)

  def __eq__(self, other):
    return self.ip == other.ip and self.port == other.port

  def __ne__(self, other):
    return not self.__eq__(other)

  def __str__(self):
    return "IP: %s\nPort: %s" % (self.ip, self.port)

  def __repr__(self):
    return self.__str__()

  def __hash__(self):
    return hash(self.raw)


class TestAddressMethods(unittest.TestCase):
  def test_port(self):
    self.assertEqual(IPAddress('1.2.3.4.5').port, '5')
    self.assertEqual(IPAddress('1.2.3.4.https').port, 'https')

  def test_ip(self):
    self.assertEqual(IPAddress('1.2.3.4.5').ip, "1.2.3.4")

  def test_short_ip(self):
    self.assertEqual(IPAddress("1.2.3.4").ip, "1.2.3.4")
    self.assertEqual(IPAddress("1.2.3.4").port, None)

  def test_failure(self):
    with self.assertRaises(ValueError):
      IPAddress('1.2.3')
    with self.assertRaises(ValueError):
      IPAddress('te.te.tx.tx.4')


class Protocol(object):
  OPEN_PAREN = "("
  CLOSE_PAREN = ")"
  TCP_TOKEN = 'TCP'
  UDP_TOKEN = 'UDP'
  VRPP_TOKEN = 'VRRP'
  IGMP_TOKEN = 'IGMP'
  PIM_TOKEN = 'PIM'
  ICMP_TOKEN = 'ICMP'
  VALID = [TCP_TOKEN, UDP_TOKEN, VRPP_TOKEN,
           IGMP_TOKEN, PIM_TOKEN, ICMP_TOKEN]

  def __init__(self, raw):
    '''
    Of the form "TCP (6)"
    '''
    self.raw = raw
    self.name = raw[:raw.find(Protocol.OPEN_PAREN)-1]
    CHECK(self.name, lambda: self.name in Protocol.VALID)
    self.value = int(raw[raw.find(Protocol.OPEN_PAREN) +
                         1:raw.find(Protocol.CLOSE_PAREN)])

  def isUDP(self):
    return self.name == Protocol.UDP_TOKEN

  def isTCP(self):
    return self.name == Protocol.TCP_TOKEN

  def __eq__(self, other):
    return self.name == other.name and self.value == other.value

  def __ne__(self, other):
    return not self.__eq__(other)

  def __str__(self):
    return "%s (%s)" % (self.name, self.value)

  def __repr__(self):
    return self.__str__()

  def __hash__(self):
    return hash(self.raw)


class TestProtocolMethods(unittest.TestCase):
  def test_name(self):
    self.assertEqual(Protocol('TCP (6)').name, 'TCP')

  def test_isX(self):
    self.assertTrue(Protocol('UDP (17)').isUDP())
    self.assertFalse(Protocol('TCP (6)').isUDP())

    self.assertTrue(Protocol('TCP (6)').isTCP())
    self.assertFalse(Protocol('UDP (17)').isTCP())

  def test_value(self):
    self.assertEqual(Protocol('TCP (6)').value, 6)

  def test_failure(self):
    with self.assertRaises(ValueError):
      Protocol('TCP 6')


def getList(flags_string):
  OPEN_LIST = "["
  CLOSE_LIST = "]"
  LIST_SEP = ","

  CHECK(flags_string, lambda:
        flags_string[0] == OPEN_LIST and flags_string[-1] == CLOSE_LIST)
  return [f.strip() for f in flags_string[1:-1].split(LIST_SEP)]


class DatagramHeader(object):
  TOS_TOKEN = "tos"
  TTL_TOKEN = "ttl"
  ID_TOKEN = "id"
  OFFSET_TOKEN = "offset"
  FLAGS_TOKEN = "flags"
  PROTOCOL_TOKEN = "proto"
  OPTIONS_TOKEN = "options"
  LENGTH_TOKEN = "length"

  def __init__(self, data):
    '''
    data should be of the form
        tos 0x0, ttl 64, id 42387, offset 0, flags [none],
        proto UDP (17), length 364
    '''
    self.data = data
    self.fields = data.split(", ")

    self.options = self.tos = self.ttl = self.id = self.offset = self.flags = self.protocol = self.length = None
    for field in self.fields:
      if field[:len(DatagramHeader.TOS_TOKEN)] == DatagramHeader.TOS_TOKEN:
        CHECK(self.tos, lambda: self.tos is None)
        self.tos = field[len(DatagramHeader.TOS_TOKEN) + 1:]
      elif field[:len(DatagramHeader.TTL_TOKEN)] == DatagramHeader.TTL_TOKEN:
        CHECK(self.ttl, lambda: self.ttl is None)
        self.ttl = int(field[len(DatagramHeader.TTL_TOKEN) + 1:])
      elif field[:len(DatagramHeader.ID_TOKEN)] == DatagramHeader.ID_TOKEN:
        CHECK(self.id, lambda: self.id is None)
        self.id = int(field[len(DatagramHeader.ID_TOKEN) + 1:])
      elif field[:len(DatagramHeader.OFFSET_TOKEN)] == DatagramHeader.OFFSET_TOKEN:
        CHECK(self.offset, lambda: self.offset is None)
        self.offset = int(field[len(DatagramHeader.OFFSET_TOKEN) + 1:])
      elif field[:len(DatagramHeader.FLAGS_TOKEN)] == DatagramHeader.FLAGS_TOKEN:
        CHECK(self.flags, lambda: self.flags is None)
        flags_string = field[len(DatagramHeader.FLAGS_TOKEN) + 1:]
        self.flags = getList(flags_string)
      elif field[:len(DatagramHeader.PROTOCOL_TOKEN)] == DatagramHeader.PROTOCOL_TOKEN:
        CHECK(self.protocol, lambda: self.protocol is None)
        self.protocol = Protocol(
            field[len(DatagramHeader.PROTOCOL_TOKEN) + 1:])
      elif field[:len(DatagramHeader.LENGTH_TOKEN)] == DatagramHeader.LENGTH_TOKEN:
        CHECK(self.length, lambda: self.length is None)
        self.length = int(field[len(DatagramHeader.LENGTH_TOKEN) + 1:])
      elif field[:len(DatagramHeader.OPTIONS_TOKEN)] == DatagramHeader.OPTIONS_TOKEN:
        CHECK(self.options, lambda: self.options is None)
        self.options = field[len(DatagramHeader.OPTIONS_TOKEN) + 1:]
      else:
        CHECK(data, lambda: False)

  def __eq__(self, other):
    return (self.tos == other.tos and self.ttl == other.ttl
            and self.id == self.id and self.offset == other.offset
            and self.flags == other.flags
            and self.protocol == other.protocol
            and self.length == other.length)

  def __hash__(self):
    return hash(self.data)

  def __ne__(self, other):
    return not self.__eq__(other)

  def __str__(self):
    return ("TOS: %s\nTTL: %s\nID: %s\nOFFSET: %s\nFLAGS: %s\n"
            "PROTOCOL: %s\nLENGTH: %s\n" % (
                self.tos, self.ttl, self.id, self.offset, self.flags, self.protocol, self.length))

  def __repr__(self):
    return self.__str__()


class TestDatagramHeader(unittest.TestCase):
  def test_fields(self):
    header = DatagramHeader("tos 0x10, ttl 64, id 9792, offset 0, "
                            "flags [DF], proto TCP (6), length 88")
    self.assertEqual(header.tos, "0x10")
    self.assertEqual(header.ttl, 64)
    self.assertEqual(header.id, 9792)
    self.assertEqual(header.offset, 0)
    self.assertEqual(header.flags, ["DF"])
    self.assertEqual(header.protocol.name, "TCP")
    self.assertEqual(header.protocol.value, 6)
    self.assertEqual(header.length, 88)


class IPPacket(object):
  START_TOKEN = "IP"
  OPEN_PAREN = "("
  CLOSE_PAREN = ")"

  COLON_TOKEN = ":"
  FLAGS_TOKEN = "Flags"
  CKSUM_TOKEN = "cksum"
  SEQ_TOKEN = "seq"
  ACK_TOKEN = "ack"
  WINDOW_TOKEN = "win"
  OPTIONS_TOKEN = "options"
  LENGTH_TOKEN = "length"

  SEP = ", "

  def __init__(self, data):
    '''
    'data' should be of the form

    IP (tos 0x0, ttl 64, id 42387, offset 0, flags [none],
        proto UDP (17), length 364) 10.30.23.135.17500 > 255.255.255.255.17500: UDP, length 336
    '''
    # Store the data and verify initial tokens,
    self.data = data
    CHECK(data, lambda: (data[:2]) == IPPacket.START_TOKEN)

    # Extract the layer three datagram's header fields and values
    start_idx = data.find(IPPacket.OPEN_PAREN)
    end_idx = data.rfind(IPPacket.CLOSE_PAREN, 0,
                         data.find(IPPacket.COLON_TOKEN))
    self.header = DatagramHeader(data[start_idx+1:end_idx])

    CHECK(self.header.protocol,
          lambda:  self.header.protocol.name in Protocol.VALID)

    # Extract the source and destination
    src_dst = [t.strip() for t in data[end_idx +
                                       1:data.find(IPPacket.COLON_TOKEN)].split(" > ")]
    CHECK(src_dst, lambda: (len(src_dst) == 2))
    self.src = IPAddress(src_dst[0])
    self.dst = IPAddress(src_dst[1])
    self.flags = self.cksum = self.seq = self.ack = self.window = self.options = self.length = None
    if self.header.protocol.name == 'TCP':
      info = [t.strip() for t in data[data.find(
          IPPacket.COLON_TOKEN) + 1:].split(IPPacket.SEP)]
      # We are invariant to ordering.
      for item in info:
        if item[:len(IPPacket.FLAGS_TOKEN)] == IPPacket.FLAGS_TOKEN:
          CHECK(self.flags, lambda:  self.flags is None)
          self.flags = getList(item[len(IPPacket.FLAGS_TOKEN) + 1:])
        elif item[:len(IPPacket.CKSUM_TOKEN)] == IPPacket.CKSUM_TOKEN:
          CHECK(self.cksum, lambda:  self.cksum is None)
          self.cksum = item[len(IPPacket.CKSUM_TOKEN) + 1:]
        elif item[:len(IPPacket.SEQ_TOKEN)] == IPPacket.SEQ_TOKEN:
          CHECK(self.seq, lambda:  self.seq is None)
          self.seq = item[len(IPPacket.SEQ_TOKEN) + 1:]
        elif item[:len(IPPacket.ACK_TOKEN)] == IPPacket.ACK_TOKEN:
          CHECK(self.ack, lambda:  self.ack is None)
          self.ack = int(item[len(IPPacket.ACK_TOKEN) + 1:])
        elif item[:len(IPPacket.WINDOW_TOKEN)] == IPPacket.WINDOW_TOKEN:
          CHECK(self.window, lambda:  self.window is None)
          self.window = int(item[len(IPPacket.WINDOW_TOKEN) + 1:])
        elif item[:len(IPPacket.OPTIONS_TOKEN)] == IPPacket.OPTIONS_TOKEN:
          CHECK(self.options, lambda:  self.options is None)
          self.options = getList(
              item[len(IPPacket.OPTIONS_TOKEN) + 1:])
        elif item[:len(IPPacket.LENGTH_TOKEN)] == IPPacket.LENGTH_TOKEN:
          CHECK(self.length, lambda:  self.length is None)
          self.length = int(item[len(IPPacket.LENGTH_TOKEN) + 1:])
        else:
          CHECK(data, lambda: False)
    else:
      self.protocol_data = data[data.find(IPPacket.COLON_TOKEN) + 1:]

  def __eq__(self, other):
    return (
        self.header == other.header
        and self.src == other.src
        and self.dst == other.dst
        and (
            (self.header.protocol.name != 'TCP'
             and self.protocol_data == other.protocol_data
             )
            or
            (self.flags == other.flags
             and self.cksum == other.cksum
             and self.seq == other.seq
             and self.ack == other.ack
             and self.window == other.window
             and self.options == other.options
             and self.length == other.length
             )
        )
    )

  def __hash__(self):
    return hash((self.header, self.src, self.dst, tuple(self.flags),
                 self.seq, self.ack, self.window, tuple(self.options),
                 self.length))

  def __ne__(self, other):
    return not self.__eq__(other)

  def __str__(self):
    if (self.header.protocol.name == 'TCP'):
      return ("\n\nHEADER:\n%s\n\nSOURCE:\n%s\n\nDEST:\n%s\n\n"
              "flags:%s\nchecksum: %s\nsequence: %s\nack: %s\n"
              "window: %s\noptions: %s\nlength: %s" % (
                  self.header, self.src, self.dst, self.flags, self.cksum,
                  self.seq, self.ack, self.window, self.options, self.length))
    return "HEADER:\n%s\n\nSOURCE:\n%s\n\nDEST:\n%s\n\nPROTOCOL DATA %s" % (
        self.header, self.src, self.dst, self.protocol_data)

  def __repr__(self):
    return self.__str__()


class TestIPPacketTest(unittest.TestCase):
  def test_fields(self):
    packet = IPPacket("IP (tos 0x0, ttl 64, id 52766, offset 0, "
                      "flags [DF], proto TCP (6), length 60) "
                      "172.20.16.98.53726 > 82.132.219.219.https: "
                      "Flags [S], cksum 0x694e (correct), seq 2720785584, win 29200, options [mss 1460,sackOK,TS val 18361006 ecr 0,nop,wscale 7], length 0")
    self.assertEqual(packet.header, DatagramHeader(
        "tos 0x0, ttl 64, id 52766, offset 0, flags [DF], "
        "proto TCP (6), length 60"))
    self.assertEqual(packet.src, IPAddress("172.20.16.98.53726"))
    self.assertEqual(packet.dst, IPAddress("82.132.219.219.https"))
    self.assertEqual(packet.flags, ["S"])
    self.assertEqual(packet.cksum, "0x694e (correct)")
    self.assertEqual(packet.seq, '2720785584')
    self.assertEqual(packet.ack, None)
    self.assertEqual(packet.window, 29200)
    self.assertEqual(packet.options, ["mss 1460", "sackOK", "TS val 18361006 ecr 0", "nop",
                                      "wscale 7"])
    self.assertEqual(packet.length, 0)


def runTests():
  TESTS = [TestIPPacketTest, TestAddressMethods,
           TestProtocolMethods, TestDatagramHeader]
  for TEST in TESTS:
    suite = unittest.TestLoader().loadTestsFromTestCase(TEST)
    unittest.TextTestRunner().run(suite)


def loadPackets():
  FILENAME = os.path.join("trace.txt")
  packets = []
  IP6 = []
  ARP = []
  with open(FILENAME) as f:
    data = None
    typ = "IP"
    for line in f.readlines():
      if line.startswith("IP") or line.startswith("ARP"):
        if data is not None:
          if typ == "IP":
            packets.append(IPPacket(data))
          elif typ == "IP6":
            IP6.append(data)
          elif typ == "ARP":
            ARP.append(data)
        data = line
        if data.startswith("IP "):
          typ = "IP"
        elif data.startswith("IP6"):
          typ = "IP6"
        elif data.startswith("ARP"):
          typ = "ARP"
      else:
        data += line
  return packets


def isMobilePacket(p):
  WEBSITE_HOST_PORT = ["80", "443"]
  return (
      # cell phone sends a SYN or ACK packet.
      (p.src.ip == CELL_IP and p.dst.port in WEBSITE_HOST_PORT and p.flags is not None and p.flags == [
       "S"] or p.flags == ["."])
      # cell receives a SYN/ACK packet.
      or (p.dst.ip == CELL_IP and p.src.port in WEBSITE_HOST_PORT and p.flags is not None and p.flags == ["S."]))

# Filter to only keep those where a SYN/SYN-ACK/ACK sequence exists.


def containsTCPHandshake(ps):
  in_sequence = sorted(ps, key=lambda p: p.header.id)
  shakes = []
  counter = 0
  for p in ps:
    # CELL_IP sends SYN packet
    if counter % 3 == 0 and "S" in p.flags and p.src.ip == CELL_IP:
      counter += 1
      shakes.append([p])
    # CELL_IP receives SYN/ACK
    elif counter % 3 == 1 and "S." in p.flags and p.dst.ip == CELL_IP:
      shakes[-1].append(p)
      counter += 1
    # CELL_IP sends ACK
    elif counter % 3 == 2 and "." in p.flags and p.src.ip == CELL_IP:
      counter += 1
      shakes[-1].append(p)
  if len(shakes) == 0:
    return []
  return shakes if len(shakes[-1]) == 3 else shakes[:-1]


# My cell phone IP.
CELL_IP = "10.30.22.101"


# 1. Find the top visited websites on 80 or 443.
def q1():
  packets = loadPackets()
  candidates = sorted([packet for packet in packets if isMobilePacket(packet)],
                      key=lambda p: p.header.id)

  # Group by server address
  server_communication = defaultdict(list)
  for p in candidates:
    server_communication[
        p.src.ip if p.src.ip != CELL_IP else p.dst.ip].append(p)

  tcp_shakes = {}
  for server, pkts in server_communication.items():
    res = containsTCPHandshake(pkts)
    if len(res) > 0:
      tcp_shakes[server] = res
  print("Five top visited websites as determined by completed TCP handshake "
        "%s" % list(tcp_shakes.keys())[:5])


# 3. Find all (sc,dst) pair packets that are SYN packets and count them
def q3():
  packets = loadPackets()
  syn_count = Counter({})
  syn_packets = defaultdict(list)
  for packet in packets:
    if packet.flags == ["S"]:
      syn_count[(packet.src.ip, packet.dst.ip)] += 1
      syn_packets[(packet.src.ip, packet.dst.ip)].append(packet)
  common = syn_count.most_common()[0]
  print("High number of SYN packets from %s to %s. Total of %s." % (
      common[0][0], common[0][1], common[1]))


# 2. Let's look for IPs with a lot of ports in the destination.
def q2():
  packets = loadPackets()
  ports = defaultdict(set)
  for packet in packets:
    ports[(packet.src.ip, packet.dst.ip)].add(packet.dst.port)
  results = [(k, sorted([int(t) for t in list(v) if t is not None]))
             for k, v in ports.items()]
  ordered_results = sorted(results, key=lambda p: -len(p[1]))
  ports_scanned = ordered_results[0][1]
  source_ip = ordered_results[0][0][0]
  destination_ip = ordered_results[0][0][1]
  print("IP %s is scanning IP %s. It has scanned %s ports from %s-%s" % (
      source_ip, destination_ip, len(ports_scanned), min(ports_scanned),
      max(ports_scanned)))


def q4():
  # Load the lines individually since we can't use the infrastructure from
  # before efficiently.
  lines = []
  full_packets = []
  full_lines = []
  with open("trace.txt") as f:
    data = None
    typ = "IP"
    for line in f.readlines():
      if line.startswith("IP") or line.startswith("ARP"):
        if data is not None:
          if typ == "IP":
            packet = IPPacket(data)
            if packet.src.ip == CELL_IP:
              lines.append(re.sub(r'cksum 0x[a-zA-Z0-9_ ()]+,',
                                  '', data))
              full_lines.append(data)
              full_packets.append(IPPacket(data))
          elif typ == "IP6":
            pass
          elif typ == "ARP":
            pass
        data = line
        if data.startswith("IP "):
          typ = "IP"
        elif data.startswith("IP6"):
          typ = "IP6"
        elif data.startswith("ARP"):
          typ = "ARP"
      else:
        data += line
  # The indexes match. Fid ducplicate indexes
  print("There are %s unique packets and %s total packets." % (
      len(set(lines)), len(lines)))
  dup_packet = []
  dup_lines = []
  for i, line in enumerate(lines):
    if line in lines[:i]:
      dup_packet.append(
          (full_packets[lines.index(line)], full_packets[i]))
      dup_lines.append(
          (full_lines[lines.index(line)], full_lines[i]))
  print("Duplicate lines: %s", dup_lines)


def runQuestions():
  q1()
  q2()
  q3()
  q4()


runTests()
runQuestions()
