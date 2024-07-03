import requests as req
from Crypto.Util.number import *
from tqdm import tqdm
cipher = '46307250616464316e674f7261636c33df777045816267cfa732822de676a7ebe5ed001c5c59e45fbafe4b08085b5001c56640a1c06683a499e1169e655ace5b'
iv = cipher[:32]
c1 = cipher[32:64]
c2 = cipher[64:96]
c3 = cipher[96:]
host = 'http://10.102.33.68:8208/'


def check_pad(txt):
    resp = req.get(host + '/dec_3', params={'data': txt})
    return resp.text[5:8]


list1 = []


def find_padding_length(c):
    data = 0
    last_byte = ''
    for i in range(256):
        data = '00' * 15 + hex(i)[2:].zfill(2) + c
        if check_pad(data) == '200':
            last_byte = hex(i)[2:].zfill(2)
            break
    data_list = [data[i:i + 2] for i in range(0, len(data), 2)]
    j = 0
    for j in range(16):
        data_list[j] = hex(int(data_list[j], 16) + 1)[2:].zfill(2)
        data = ''.join(data_list)
        if check_pad(data) != '200':
            break
    return 16 - j, last_byte

print("\033[92m=====================================开始计算填充长度=====================================\033[0m")
len1 ,last_byte1= find_padding_length(c1)
len2 ,last_byte2= find_padding_length(c2)
len3 ,last_byte3= find_padding_length(c3)
print(f"分组1填充的长度为:{len1}，最后一个字节为:{last_byte1}")
print(f"分组2填充的长度为:{len2}，最后一个字节为:{last_byte2}")
print(f"分组3填充的长度为:{len3}，最后一个字节为:{last_byte3}")


def Padding_Oracle_Attack(block,last_byte):
    a_list = []
    a_list.append(hex(int(last_byte, 16) ^ 0x01)[2:].zfill(2))
    for i in tqdm(range(15)):
        r_list=[]
        for j in range(i+1):
            r_list.append(hex(int(a_list[j], 16) ^ (i + 2))[2:].zfill(2))
        for k in range(256):
            R_list=r_list[::-1]
            txt='00'*(14-i)+hex(k)[2:].zfill(2)+"".join(R_list)+block
            if check_pad(txt)=='200':
                a_list.append(hex(k^(i+2))[2:].zfill(2))
                break
        r_list.clear()
        if len(a_list)==16:
            break
    a=''
    for i in range(16):
        a+=a_list[15-i]
    return a
print("\033[92m=====================================Padding Oracle Attack=====================================\033[0m")
a3=Padding_Oracle_Attack(c3,last_byte3)
a2=Padding_Oracle_Attack(c2,last_byte2)
a1=Padding_Oracle_Attack(c1,last_byte1)

print('a1:',a1)
print('a2:',a2)
print('a3:',a3)
m3=hex(int(a3,16)^int(c2,16))[2:]
m2=hex(int(a2,16)^int(c1,16))[2:]
m1=hex(int(a1,16)^int(iv,16))[2:]
print('m1:',m1)
print('m2:',m2)
print('m3:',m3)
m=m1+m2+m3
print('m:',m)
print("明文为:",long_to_bytes(int(m,16)))
