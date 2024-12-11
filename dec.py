from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import glob
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

#sk = receiver private key, Ck= encryted symmetric key, k=symmetric key 
"""

file_in = open("Ck.bin", "rb")
sk =RSA.import_key(open("private.pem").read())
Ck = file_in.read(sk.size_in_bytes())
cipher_rsa = PKCS1_OAEP.new(sk)
k = cipher_rsa.decrypt(Ck)
print(k)
file_in.close()




#CM=ciphertext, M=message
try:
	with open('iv', 'r') as file:
    		iv = file.read()
#	iv = b64decode("MLqyMmiQ1RCreg1htCMSBg==")
	CM = b64decode("T9W3Y+1Ta4gX6+rSpmBmMB9xqhfX0DZ15smMlvAMpPc=")
	cipher = AES.new(k, AES.MODE_CBC, iv)
	M = unpad(cipher.decrypt(CM), AES.block_size)
	print("The message was: ", M)
except ValueError:
	print("Incorrect decryption")

"""
file_in = open("Ck.bin", "rb")
sk =RSA.import_key(open("private.pem").read())
Ck = file_in.read(sk.size_in_bytes())
cipher_rsa = PKCS1_OAEP.new(sk)
k = cipher_rsa.decrypt(Ck)
#	print(k)
file_in.close()


for item in glob.glob("*.txt"):	

	#CM=ciphertext, M=message
	try:

		iv = b'H\xd7v1\x16\xa6\x88GQ\xaehE>0!\x86'
		with open(item, 'r') as file:
	    		CM_bytes = file.read()	
		CM = b64decode(CM_bytes)
		cipher = AES.new(k, AES.MODE_CBC, iv)
		M = unpad(cipher.decrypt(CM), AES.block_size)
#		print("The message was: ", M)
		decrypted_content = M.decode("utf-8")
		with open(item, 'w') as file:
	    		file.write(decrypted_content)
	except ValueError:
		print("Incorrect decryption")

