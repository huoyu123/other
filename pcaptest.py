from scapy.all import *
import binascii
import bson
import time


pks = []

def parse_mongo(s):
    if len(s) < 28:
        return
    request_header = struct.unpack('<4I', s[:16])
    if (2004 == request_header[3]):
        flag = struct.unpack('<I', s[16:20])
        a = s[20:].index('\x00') + 1
        sp = "%ds" % a
        db = struct.unpack(sp, s[20:20 + a])
        # print(db)
        skip, ret = struct.unpack("<2i", s[20 + a:28 + a])
        # print(skip,ret)
        bson_obj = bson.BSON(s[28 + a:]).decode()
        return (request_header[3], request_header[1], time.time(), bson_obj)

    elif (1 == request_header[3]):
        flag = struct.unpack('<iq2i', s[16:36])
        # print(flag)
        bson_obj = bson.decode_all(s[36:])
        return (request_header[3], request_header[2], time.time(), bson_obj)
    return


def parse_mysql(s):
    if len(s) < 5:
        return
    print(binascii.b2a_hex(s[:5]))
    request_header = struct.unpack('<IB', s[:5])
    if (3 == request_header[1]):
        sql = struct.unpack('%ss' % (request_header[0] - 1), s[5:5 + request_header[0]])
        print(sql)

def parse_http(s):
    pdata = None
    try:
        pdata = s.getlayer(Raw).load
        if 'GET '==pdata[:4]:
       #     print(pdata)
       #     print(s.time)
       #     print(s.getlayer(TCP).seq,s.getlayer(TCP).ack,s.len)
            pks.append(s)
        elif 'POST '==pdata[:5]:
            pks.append(s)
            #print(pdata)
        elif 'HTTP/'==pdata[:5]:
            #print(s.time)
            for pk in pks:
                if s.getlayer(TCP).seq==pk.getlayer(TCP).ack:
                    print("request url: %s execute time: %s" %(pk.getlayer(Raw).load,s.time-pk.time))
                    pks.remove(pk)
        else:
            pass
    except Scapy_Exception as e:
        print(e)

    except AttributeError as e:
        pass


def parse_kafka(s):
    if len(s) < 12:
        return
    # print(binascii.b2a_hex(s[:12]))
    # index = s[:12].index("\x00")+1
    # print(index)
    # print(s[8:])
    request_header = struct.unpack('<2HI', s[:8])
    if 0 == request_header[0]:
        request = struct.unpack('<HI', s[8:14])
        print(request)
    print(s[14:])


def main(x):
    try:
        data = x.getlayer(Raw).load
        parse_kafka(s=data)
        # parse_mysql(s=data)
        #  ret = parse_mongo(s=data)
        #  if ret is None:
        #      return
        #  if 1 == ret[0]:
        #      for l in retlist:
        #          if l[1] == ret[1]:
        #              if ret[2] - l[2] > 0.01:
        #                  print(ret[2] - l[2], l[3])
        #                  ip = x.getlayer(IP)
        #                  print(ip.src,ip.dst)
        #              retlist.remove(l)
        #  else:
        #      retlist.append(ret)
        #
    except AttributeError as e:
        # print(e)
        pass
    except bson.errors.InvalidBSON as e:
        # print(e)
        pass
    except struct.error as e:
        # print(e)
        pass

def parse_xlrtdp(pk):
    try:
        pdata = pk.getlayer(Raw).load
        # print(dir(pk))
        h_len = struct.unpack('<B', pdata[:1])[0] >> 4 << 2
        if len(pdata) < 15:
            return
        if (pdata[:4] == "GET "):
            print("time: %f src ip: %s dst ip: %s http req :%s " % (
            pk.time, pk.getlayer(IP).src, pk.getlayer(IP).dst, pdata.replace('\r\n', '\\r\\n')))
        elif (pdata[:4] == "HTTP"):
            print("time: %f src ip: %s dst ip: %s http resp :%s " % (
            pk.time, pk.getlayer(IP).src, pk.getlayer(IP).dst, pdata.replace('\r\n', '\\r\\n')))
        elif h_len == 12:
            # print(binascii.b2a_hex(pdata))
            b = struct.unpack('<BB5H', pdata[:12])
            head_len = (b[0] >> 4)
            ver = (b[0] & 0xf)
            f1 = b[4] & 0x01
            f2 = b[4] >> 1 & 0x01
            f3 = b[4] >> 2 & 0x01
            f4 = b[4] >> 3 & 0x01
            extdata_len = b[4] >> 4
            extend = pdata[12:12 + extdata_len]
            data = pdata[12 + extdata_len:]
            # print(ver,head_len,b[1],b[2],b[3],f1,f2,f3,f4,extdata_len,b[5],b[6])
            if (f4):
                key = ((b[1] ^ b[3]) & 255)
                dl = b[2] - (head_len << 2) - extdata_len
                if dl > 0:
                    i = dl - 1
                    while i > 0:
                        ret = chr(ord(data[i:i + 1]) ^ ord(data[i - 1:i]))
                        data = data[:i] + ret + data[i + 1:]
                        i -= 1
                    if extdata_len > 0:
                        ret = chr(ord(data[:1]) ^ ord(extend[extdata_len - 1:extdata_len]))
                        data = ret + data[1:]
                    else:
                        ret = chr(ord(data[:1]) ^ key)
                        data = ret + data[1:]
                if extdata_len > 0:
                    i = extdata_len - 1
                    while i > 0:
                        ret = chr(ord(extend[i:i + 1]) ^ ord(extend[i - 1:i]))
                        extend = extend[:i] + ret + extend[i + 1:]
                        i -= 1
                    ret = chr(ord(extend[:1]) ^ key)
                    extend = ret + extend[1:]
                print("time: %f src ip: %s dst ip: %s extend :%s  data test1: %s" % (
                pk.time, pk.getlayer(IP).src, pk.getlayer(IP).dst, extend, data))
            else:
                print("time: %f src ip: %s dst ip: %s extend :%s  data test1: %s" % (
                pk.time, pk.getlayer(IP).src, pk.getlayer(IP).dst, extend, data))
        else:
            h_ws = struct.unpack('<2B', pdata[:2])
            opcode = (h_ws[0] & 0xf)
            fin = h_ws[0] >> 7 & 0x01
            if opcode == 1 and pk.getlayer(TCP).sport == 80:
                ret = pdata[2:].replace('\r\n', '\\r\\n')
                print("time: %f src ip: %s dst ip: %s websocket_data: %s" % (
                pk.time, pk.getlayer(IP).src, pk.getlayer(IP).dst, ret))
            else:
                #print(binascii.b2a_hex(pdata))
                pass
                # print(pdata[2:])
                # print("time: %f src ip: %s dst ip: %s websocket_data: %s" % (pk.time, pk.getlayer(IP).src, pk.getlayer(IP).dst, ret))
        print("-------------------------------------------------------------------------------------------------")
    except Scapy_Exception as e:
        print(e)

    except AttributeError as e:
        pass

def read_pcap(filename):
    pkts = rdpcap(filename)
    for pk in pkts:
        try:
            pdata = pk.getlayer(Raw).load
            #print(dir(pk))
            h_len = struct.unpack('<B',pdata[:1])[0] >> 4 << 2
            if len(pdata) < 15:
                continue
            if (pdata[:4] == "GET "):
                print("time: %f src ip: %s dst ip: %s http req :%s " % (pk.time, pk.getlayer(IP).src, pk.getlayer(IP).dst, pdata.replace('\r\n','\\r\\n')))
            elif (pdata[:4] == "HTTP"):
                print("time: %f src ip: %s dst ip: %s http resp :%s " % (pk.time, pk.getlayer(IP).src, pk.getlayer(IP).dst, pdata.replace('\r\n','\\r\\n')))
            elif h_len == 12:
                #print(binascii.b2a_hex(pdata))
                b = struct.unpack('<BB5H', pdata[:12])
                head_len = (b[0] >> 4)
                ver = (b[0] & 0xf)
                f1 = b[4] & 0x01
                f2 = b[4] >> 1 & 0x01
                f3 = b[4] >> 2 & 0x01
                f4 = b[4] >> 3 & 0x01
                extdata_len = b[4] >> 4
                extend = pdata[12:12 + extdata_len]
                data = pdata[12 + extdata_len:]
                #print(ver,head_len,b[1],b[2],b[3],f1,f2,f3,f4,extdata_len,b[5],b[6])
                if (f4):
                    key = ((b[1] ^ b[3]) & 255)
                    dl = b[2] - (head_len<< 2) - extdata_len
                    if dl > 0:
                        i = dl - 1
                        while i > 0:
                            ret = chr(ord(data[i:i + 1]) ^ ord(data[i - 1:i]))
                            data = data[:i] + ret + data[i + 1:]
                            i -= 1
                        if extdata_len > 0:
                            ret = chr(ord(data[:1]) ^ ord(extend[extdata_len - 1:extdata_len]))
                            data = ret + data[1:]
                        else:
                            ret = chr(ord(data[:1]) ^ key)
                            data = ret + data[1:]
                    if extdata_len > 0:
                        i = extdata_len - 1
                        while i > 0:
                            ret = chr(ord(extend[i:i + 1]) ^ ord(extend[i - 1:i]))
                            extend = extend[:i] + ret + extend[i + 1:]
                            i -= 1
                        ret = chr(ord(extend[:1]) ^ key)
                        extend = ret + extend[1:]
                    print("time: %f src ip: %s dst ip: %s extend :%s  data test1: %s" % (pk.time, pk.getlayer(IP).src, pk.getlayer(IP).dst, extend, data))
                else:
                    print("time: %f src ip: %s dst ip: %s extend :%s  data test1: %s" % (pk.time, pk.getlayer(IP).src, pk.getlayer(IP).dst, extend, data))
            else:
                h_ws = struct.unpack('<2B',pdata[:2])
                opcode = (h_ws[0] & 0xf)
                fin = h_ws[0] >>7  & 0x01
                if opcode == 1 and pk.getlayer(TCP).sport == 80:
                    ret = pdata[2:].replace('\r\n','\\r\\n')
                    print("time: %f src ip: %s dst ip: %s websocket_data: %s" % (pk.time, pk.getlayer(IP).src, pk.getlayer(IP).dst, ret))
                else:
                    #print(binascii.b2a_hex(pdata))
                    pass
                    #print(pdata[2:])
                    #print("time: %f src ip: %s dst ip: %s websocket_data: %s" % (pk.time, pk.getlayer(IP).src, pk.getlayer(IP).dst, ret))
            print("-------------------------------------------------------------------------------------------------")
        except Scapy_Exception as e:
            print(e)

        except AttributeError as e:
            pass



#read_pcap(filename='/root/backup/test.pcap')
# global retlist
# retlist = []
sniff(iface='eth0',filter="tcp and port 7000",prn=lambda x:parse_http(x))
#sniff(iface='eth0',filter="tcp and port 80",prn=lambda x:parse_xlrtdp(x))
# sniff(iface='eth0',filter="tcp and dst port 9092",prn=lambda x:main(x))
##sniff(iface='eth0',filter="tcp and port 8066",prn=lambda x:main(x))
##sniff(iface='eth0',filter="tcp and port 27017",prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))
