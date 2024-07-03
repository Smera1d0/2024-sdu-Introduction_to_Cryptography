import socket
import hashlib
import hmac
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import datetime
import os
import time
print("\033[1;32m---------持卡人服务器---------\033[0m")
def generate_certificate(subject_name):
    # 生成私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 生成证书主题和颁发者
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    issuer = subject  # 自签名证书，颁发者是自己

    # 生成证书
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # 证书有效期为1年
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())

    # 返回私钥和证书
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    return private_key_pem.decode('utf-8'), cert_pem.decode('utf-8')
def sign_message(private_key_pem, message):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    signature = private_key.sign(
        message.encode(),
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')
def verify_signature(public_key_pem, message, signature):
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False
def extract_public_key_from_cert(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    public_key = cert.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_pem.decode('utf-8')
def hash_message(message):
    hashed = hashlib.sha256(message.encode()).hexdigest()
    return hashed
def encrypt_rsa(public_key_pem, plaintext):
    # 加载公钥
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    # 加密数据
    ciphertext = public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext
def generate_temp_aes_key():
    aes_key = hashlib.sha256(os.urandom(32)).digest()[:16]  # 生成随机的32字节并截取16字节作为AES密钥
    return aes_key
def encrypt_message(pk, message):
    cipher = AES.new(pk, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct


# 定义节点1的IP地址和端口号
HOST = 'localhost'
PORT = 5000
#持卡人自己的私钥、证书和公钥
#商家、支付网关的证书和公钥
privte_key_c='''-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxzILhM4ivTZKm
erhf8RHZXZoPjExtEywdZDz8GQw2egRRXhgjXk1wSJj7YevEm3enm1J6/lRpeCO7
csrP10K53qlVqQAWB6i+C2bqUH2FHqNvCn/W59s9EX6OzDPA0HPeJdwpOsCHOTv7
ubaKhotQmkR+txLOgPIu7Fx19+8xuskKj/nmGs+vcnbTglOTzm1sC2l5ggPJrSnN
4ys4LzPKjEUCRgOQ3HTehLNlN9d+HYTwNEbJt/7BPvnONE90QQakaJQEnFq/HPDi
b2xgYlTCRetjU2/WGwwUyHm875SKL1/n54HheleJCcpjt3nFWG0aXKkUZi0KgpX6
MEgGt5AbAgMBAAECggEAIca6LlH961+PNnUlxYQkYei4Na/vbOExhjveof2YJlkz
rMl1SHLHv0brWQYXJfhq2LpXBup92rNqBlgeUzGPiYPVI2LBk23NDp1X5bd4wOs7
HQMfmhHdwlIqerIsOrre6BrFIkf4/zdOP9nd5Z79pEhKLtBUkEpKt8NLJVX+aLHD
UWR6IxqNIy+u51CAhqMRvwmBdj80UUON34VOB1rqRPU7Zd/oI3LlAfbmyO6HnPuj
mjT3C3Kn+GDDOpB4+6bRstJUdX51097v/x3SgG3s2YHe0YYNis0viw/jXdk8ZHaX
c5nqyKkCxQA4TW6FrDwhOkJPJWukPZNPVrfLLdZHQQKBgQD2AFxrhjZZPpDdxmXs
XhPVzI8YMBf5z2/6zrjfqZFiXd5ApWLM3OAuvxpmvFJ5gwVtRPvL9ydVx8X8IBuq
AD17baWYlUpNlVFXXfHkDWUjEhq5IYInsm8wFOy0FTu1g2ADXlDXgB3kC9Q9TFwf
xMCb3ZyTem9x/VzGTb3hD5hK6wKBgQC5BoEgapIV2Erf7ejgoIma6SesTOVmnxGR
d8JXeDmwCLdi2BxgYByBkjIRHWpvTeSiOG40KYInsu3VbtpaHEyiqYofLPfBh0vz
s9QQ+cf+auZ4eBV8RIPMCb10W3yNxVHPZOsgmfPiHR88H8/Al6W6fMprOmpWrrwv
SZn3UeUjkQKBgQCs1ugYa/33iiwChgjKn/bTupu3ZOMTk5mb4G6oRt1s/YLQbOMU
CQRCE+ca06om0dWYRmWbkxVCAdCrKmwFb5HDDPDSWeIQzJ6QAeOYVYj/sRKxjEeE
WKwiXjFI/bor+BgXhcbLAqr9tQnz35jCgVzKplQCkn2G23q5oZmNbYWU7QKBgCiV
c6dPmOFvwuShQ45ZyDURZSFW8I50356fvSIAfe7NyqPEsVy2WCpXjeHRKPJnDHpE
lG+elyzsA1zoZr6TLIAVXfV+oI1zhsZasG5Uy3hTrF/KPzQ1tw7/J+4ozwYtvMcX
5LcO7b6wEpTWiXQ+Dxz7mE6yznZa924L39iuvurxAoGABA5QC1zI355cexifyHH7
GFR2FZFyhMqULNQ/1m8TAiC/fiqUZHk8CGj6oT5BFw95yXp4Mhwo54tQuu5BFq8/
UPITN6+ArOLX+p/lJ38yVtDYG0i+VjdvfD1d1Lf1wsz8VKPkYpFHJzBBW1/BYJoW
rQvBVbo5j9XnM4noPRykYiE=
-----END PRIVATE KEY-----'''
cert_c='''-----BEGIN CERTIFICATE-----
MIIDbjCCAlagAwIBAgIUC9JVkHRf+Qxmi5ts6HLi5jeELL0wDQYJKoZIhvcNAQEL
BQAwZDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM
DVNhbiBGcmFuY2lzY28xEzARBgNVBAoMCk15IENvbXBhbnkxEzARBgNVBAMMCkNh
cmRob2xkZXIwHhcNMjQwNjIwMDQxODQzWhcNMjUwNjIwMDQxODQzWjBkMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5j
aXNjbzETMBEGA1UECgwKTXkgQ29tcGFueTETMBEGA1UEAwwKQ2FyZGhvbGRlcjCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALHMguEziK9NkqZ6uF/xEdld
mg+MTG0TLB1kPPwZDDZ6BFFeGCNeTXBImPth68Sbd6ebUnr+VGl4I7tyys/XQrne
qVWpABYHqL4LZupQfYUeo28Kf9bn2z0Rfo7MM8DQc94l3Ck6wIc5O/u5toqGi1Ca
RH63Es6A8i7sXHX37zG6yQqP+eYaz69ydtOCU5PObWwLaXmCA8mtKc3jKzgvM8qM
RQJGA5DcdN6Es2U3134dhPA0Rsm3/sE++c40T3RBBqRolAScWr8c8OJvbGBiVMJF
62NTb9YbDBTIebzvlIovX+fngeF6V4kJymO3ecVYbRpcqRRmLQqClfowSAa3kBsC
AwEAAaMYMBYwFAYDVR0RBA0wC4IJbG9jYWxob3N0MA0GCSqGSIb3DQEBCwUAA4IB
AQBO6VgXzg5Jv7XpDSNby9sFJCMXwDk7fttr+jOGfwU7TeeJQSZbnAd3IsAMGU6e
dIetKbHo4N5OTQG1OE6wXAzP+D81JGhURmuNZqVsxOfM98qcIIyxzWKr8tlTvUHb
SxzlIwLgoTPfKhQoZOmO5a+PSpSuHvGg+wG01+ocl2VrwORV2oZX/DMl2FYN/K8+
GJ6s4cATn+MQGx0R93Tbe43PBi6iDYVW+GYImi1R/S5uaWEDtQhTrZZSiCS+b3Za
N6AnLwZMDJkyM7RMkFMUeVbg8RdN8a/N0Fqef28g1ZqbX8sLvMrkog3ivzm0pQI5
BdkezHmFOINRw41Oy2uWrCVa
-----END CERTIFICATE-----'''
public_key_c=extract_public_key_from_cert(cert_c)
cert_p='''-----BEGIN CERTIFICATE-----
MIIDdjCCAl6gAwIBAgIUJkGsU4euRGxeHi3OCSVu76cvp8owDQYJKoZIhvcNAQEL
BQAwaDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM
DVNhbiBGcmFuY2lzY28xEzARBgNVBAoMCk15IENvbXBhbnkxFzAVBgNVBAMMDlBh
eW1lbnRHYXRld2F5MB4XDTI0MDYyMDA0MTg0M1oXDTI1MDYyMDA0MTg0M1owaDEL
MAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBG
cmFuY2lzY28xEzARBgNVBAoMCk15IENvbXBhbnkxFzAVBgNVBAMMDlBheW1lbnRH
YXRld2F5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxnGfXkYllEd1
MMnaQtd3MG/bWBaJ4zKD+ZxYy62FxBvTtM9mDZYUR7NRnJHy1rzXLP8XgEhAKL6f
QUd0Vyfw16TlsbEiWyYUCdsWrZ+4JRDXffJgTDhmoZbGzZHAF/9VMmKbtHAxK9e4
shur4x/0SI7xIVsUw8EzGggjgdyipsvi12jWdotaHRjeNPGLzKQacJ35uiusKi3u
+0bLweJ5tan9uCNUdl7L6ALPkmGMKcEEbl8lw1fWmnuGwLBEYV2n7c8Y/yp0FxOB
mBUqn904h4LEcubhCDLdLUxryDfhi9H4PIBYg4RccEwzc3yg98DJFQNA3sFYxMem
dXXFI/u2QQIDAQABoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcN
AQELBQADggEBABGY16ofa+49jCdF6qbhg5f3PxnBrCPsQuKpfwwLMdTuQLjwzJoR
eDO6v+XYQj1s0slf9iqkwKobWOKjqCA5Sqh6w2YhCKBxfQhLURGGSPlzJCciRqCR
HMLIJAEA7k3aRJ1Oitu6afhtnaIruYaTSkIc/tT40OaEdUeQtotva+jk2UggcZZl
cXbno8lyT3BY67lo3ISOLo9uZKXoCj6OE5ll4OHrFASCGeuLh73Y/CvUL46n+0Ft
FBbj69Tr0Pn3emJ02/9gV6ayhk46YYVFUyf9UCb7lpoOBHSpCf8T5jugrSO0rbo4
tVVmmUSUKIvwfrbcqSPjBu2BQI3U7zuZK0c=
-----END CERTIFICATE-----'''
public_key_p=extract_public_key_from_cert(cert_p)
cert_m='''-----BEGIN CERTIFICATE-----
MIIDajCCAlKgAwIBAgIULzr6SHSL1qO/HDw+KNwCmFoxnhwwDQYJKoZIhvcNAQEL
BQAwYjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM
DVNhbiBGcmFuY2lzY28xEzARBgNVBAoMCk15IENvbXBhbnkxETAPBgNVBAMMCE1l
cmNoYW50MB4XDTI0MDYyMDA0MTg0M1oXDTI1MDYyMDA0MTg0M1owYjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lz
Y28xEzARBgNVBAoMCk15IENvbXBhbnkxETAPBgNVBAMMCE1lcmNoYW50MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtShDTbta3kZaPMLMfRSN6ry81Y64
1vWgjsZduPNsbNYd0fbbo3Grr7wvTM5JTtyrIZIR1qjIKjNMDXfMvnHbfg60fNVE
RLbdr9RhWDbw8miu+Wq9XOJdEBI22o37iJsCOVQIQVgAfCssRZjXteIt9hSn01Xc
Q0b1R/hKZrcEBuy378HXYXWrauQKah0zzEiPdFszzQTBJHgeaS97jaMj7V1agu5F
i5OiB425e4ZP5Uv3HN2bOuTqzzHEAOjYmnyQnSShc67wpjK4yMB7HWQ19iLrYrU/
HfOEKMfKPK99eXePYBKMvAz+4UE2HOdsP4T+FbtdOvQq3386WIgv+xqTyQIDAQAB
oxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEBACeG
Z5rfixWQO/aoqIdcWJSUaHNMzKfSmH2eV6OMS3qCmDoEbO1GM7F4Uk7GCE+3GA0T
3Ib7V9gspmDCSf3ZqdOtH23o8IW+cxrMdV7laImrqThVO5sWUITpcs6h8acEqIiG
1+rYApT8UTqSdMmXJR5GZGItuvbw6NFfFd8zaEahEWw6BL+2RTcVx+lapGV0+DAx
zbgy5dWX1dLbg3FDXLEXVFIQOsTHy6ry2M7LkoGsknfWWHOsxW2ICiDqXwrMDV8X
Vn40S3W2lP8mmRdcdjM5mhEDdddFBl8l8gRAjhEFxfmmUppwgJ2ZqpispJFhDtXH
VNxXeqQ/zdqDFAi0aPg=
-----END CERTIFICATE-----'''
public_key_m=extract_public_key_from_cert(cert_m)


acc="111-222-333"
# 创建socket对象
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
print("持卡人连接到商家")
start=time.time()
# 发送购买请求
purchase_request = "Purchase request from Cardholder"
client_socket.sendall(purchase_request.encode())
print("\033[1;35mstep1:发送购买请求\033[0m")
print(purchase_request)
print()

# 等待商家的回应
response = client_socket.recv(1024)
print(f"持卡人收到回应: {response.decode()}")

#持卡人接收商家的证书
cert_m = client_socket.recv(2048)
print(f"持卡人收到商家的证书")

#持卡人验证商家的证书
sig1=client_socket.recv(2048)
print(f"持卡人收到商家的签名")
public_key_m=extract_public_key_from_cert(cert_m.decode())
#print(f"商家的公钥为: {public_key_m}")
print("\033[1;35mstep3:验证回应合法性\033[0m")
if verify_signature(public_key_m,hash_message(response.decode()),sig1.decode()):
    print("商家的签名验证成功")
else:
    print("商家的签名验证失败")
    

#持卡人发送订单和支付信息
print("\033[1;35mstep4:发送订单和支付信息\033[0m")
order_info = "Order information"
pay_info = "Payment information"
import time,string,random
def generate_nonce(length=16):
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
timetamp=str(int(time.time()))[:3]
nounce=generate_nonce()
id=generate_nonce()


print(f"订单信息: {order_info}")
print(f"支付信息: {pay_info}")
print(f"时间戳: {timetamp}")
print(f"随机数: {nounce}")
print(f"ID: {id}")



print()

sig2=sign_message(privte_key_c,hash_message(hash_message(order_info)+hash_message(pay_info)))
#print(sig2)
client_socket.sendall(sig2.encode())
#加密的OI
sd1=encrypt_rsa(public_key_m.encode(),order_info.encode())
client_socket.sendall(sd1)
sd2=hash_message(pay_info)
client_socket.sendall(sd2.encode())
#持卡人发送证书
client_socket.sendall(cert_c.encode())

#生成临时密钥
tmp_key1 = generate_temp_aes_key()
sd3 = encrypt_rsa(public_key_p.encode(),acc.encode()+tmp_key1)
sd4=encrypt_message(tmp_key1,sig2.encode()+hash_message(order_info).encode()+pay_info.encode())
#print(sd3)
#print(sd4)

client_socket.sendall(sd3)
client_socket.sendall(sd4.encode())


print("\033[1;35mstep12:验证回应合法性\033[0m")
#持卡人收到商家的发货信息
RES2=client_socket.recv(256)
print("持卡人收到发货信息：",RES2.decode())
end=time.time()
#print("耗时：",end-start)

