def find_function_arg(addr):
  while True:
    addr = idc.PrevHead(addr)
    if GetMnem(addr) == "mov" and "edx" in GetOpnd(addr, 0):
      return GetOperandValue(addr, 1)
  return ""

def get_string(addr):
  out = ""
  while True:
    if Byte(addr) != 0:
      out += chr(Byte(addr))
    else:
      break
    addr += 1
  return out

def decode_string(s):
    v = []
    for c in list(s):
        i = 'amNFHufoTRn0P3vI8xBS4t6jM9CqXeibUDEpQ1ZGYywJzAg7sk2lc5WLOrKdhV'.find(c)
        if i != -1:
            v.append('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[i])
        else:
            v.append(c)           
    return "".join(v)
    

DecodeFunction = 0x0ABA6FA8
for addr in XrefsTo(DecodeFunction, flags=0):
    ref = find_function_arg(addr.frm)
    s = decode_string(get_string(ref))
    MakeComm(addr.frm,s)
    MakeComm(ref,s)
    print 'Decode string at 0x%x as %s' % (addr.frm,s)