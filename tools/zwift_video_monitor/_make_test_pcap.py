import struct, socket, sys, time

LOCAL = '192.168.1.50'
out = sys.argv[1]

def eth(payload, ethertype=0x0800):
    return b'\x00' * 12 + struct.pack('!H', ethertype) + payload

def ipv4(src, dst, proto, payload, total_len=None):
    tl = total_len or (20 + len(payload))
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tl, 1, 0, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload

def tcp(sport, dport, payload):
    return struct.pack('!HHIIBBHHH', sport, dport, 1, 1, 5 << 4, 0x18, 65535, 0, 0) + payload

def udp(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload

def dns_name(n):
    return b''.join(bytes([len(l)]) + l.encode() for l in n.split('.')) + b'\x00'

def dns_query(name):
    return struct.pack('!HHHHHH', 1, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack('!HH', 1, 1)

def dns_response(name, cname, ip):
    q = dns_name(name) + struct.pack('!HH', 1, 1)
    ans = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 60, len(dns_name(cname))) + dns_name(cname)
    ans += dns_name(cname) + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(ip)
    return struct.pack('!HHHHHH', 1, 0x8180, 1, 2, 0, 0) + q + ans

def client_hello(sni):
    sni_b = sni.encode()
    ext_sni = struct.pack('!HH', 0, len(sni_b) + 5) + struct.pack('!HBH', len(sni_b) + 3, 0, len(sni_b)) + sni_b
    exts = ext_sni + struct.pack('!HH', 0x0017, 0)
    body = b'\x03\x03' + b'\x11' * 32 + b'\x00' + struct.pack('!H', 4) + b'\x13\x01\x13\x02' + b'\x01\x00'
    body += struct.pack('!H', len(exts)) + exts
    hs = b'\x01' + struct.pack('!I', len(body))[1:] + body
    return b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs

pkts = []
t = time.time()
pkts.append(eth(ipv4(LOCAL, '8.8.8.8', 17, udp(5555, 53, dns_query('video.zwift.com')))))
pkts.append(eth(ipv4('8.8.8.8', LOCAL, 17, udp(53, 5555, dns_response('video.zwift.com', 'zwift.akamaized.net', '23.1.2.3')))))
pkts.append(eth(ipv4(LOCAL, '23.1.2.3', 6, tcp(50000, 443, client_hello('video.zwift.com')))))
# 100 big inbound packets, truncated to 200 bytes but with total length 1500
for i in range(100):
    pkts.append(eth(ipv4('23.1.2.3', LOCAL, 6, tcp(443, 50000, b'\x17\x03\x03' + b'A' * 150), total_len=1500)))
pkts.append(eth(ipv4(LOCAL, '1.2.3.4', 6, tcp(50001, 80, b'GET /gameassets/x.m3u8 HTTP/1.1\r\nHost: cdn.zwift.com\r\n\r\n'))))
pkts.append(eth(ipv4('1.2.3.4', LOCAL, 6, tcp(80, 50001, b'HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\n\r\n#EXTM3U'))))
pkts.append(eth(ipv4(LOCAL, '5.6.7.8', 17, udp(50002, 443, b'\xc3\x00\x00\x00\x01' + b'Q' * 100))))

with open(out, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, p in enumerate(pkts):
        f.write(struct.pack('<IIII', int(t) + i, 0, len(p), len(p)))
        f.write(p)
print('wrote', out, len(pkts))
