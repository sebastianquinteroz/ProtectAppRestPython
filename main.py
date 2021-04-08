import requests
from simple_rest_client.api import API
import base64

#https://pypi.org/project/simple-rest-client/

host = "192.168.222.142" #CM IP
User = "protectappuser" #user in CipherTrust Manager
Password = "1rrw1paIxZi5LClncSSG*" #user password in CipherTrust Manager//ldap if linked
KeyName = "aes256"
##Make it 16 bytes multiple
buff_len = 32 #buffer size in bytes sent in each REST request
File_new = "file.txt"
File_enc = "file2.txt"
File_clear = "file3.txt"


#API REST URL
endpoint = "https://" + host + "/api/v1"
verify=False; #should be true in prod environments

api = API(
     api_root_url=endpoint+'/auth', # base api url
     params={}, # default params
     headers={}, # default headers
     timeout=2, # default timeout in seconds
     append_slash=False, # append slash to final url
     json_encode_body=True, # encode body as json
     ssl_verify=False # should be True in prod environments
)

#authentication
api.add_resource(resource_name="tokens")
data = {'token_type':"password",
        'username':User,#user in CipherTrust Manager
        'password':Password} #user password in CipherTrust Manager//ldap if linked
response = api.tokens.create(body=data)#authentication request
response=response.body
jwt=response["jwt"]#authentication token

#print(jwt)

#headers for encrypt and decrypt requests. It includes the authentication toekn
headers = {'Authorization': 'Bearer ' + jwt, 'Accept': 'application/json', 'Host': host,
                   'Accept-Encoding': 'gzip, deflate, br', 'Content-Type': 'application/json'}

api = API(
     api_root_url=endpoint+'/crypto', # base api url
     params={}, # default params
     headers=headers, # default headers
     timeout=2, # default timeout in seconds
     append_slash=False, # append slash to final url
     json_encode_body=True, # encode body as json
     ssl_verify=False
)

#encrypt
api.add_resource(resource_name="encrypt")

#Initialization vector. Required for CBC cypher mode
iv_initial = "AQIDBAUGBwgJCgsMDQ4QEQ=="

pad = "none" #Set pad mode to none until the last block
iv = iv_initial #Initialization vector. Required for CBC cypher mode
file_to_encrypt=open(File_enc, 'wb')#open file

with open(File_new, 'rb') as f:
    while 1:
        byte_s = f.read(buff_len)#read file in buff_len blocks until the end of file
        if not byte_s:
            break
        data_base64 = base64.b64encode(byte_s).decode("utf-8")#encode to base64
        #print("Plain text in base 64: " + data_base64)

        if len(byte_s) < buff_len:#if block less than buffer, it means end of file and padding should be set PKCS5
            pad = "PKCS5"

        data = {'plaintext': data_base64,#set plain text in request
                'id': KeyName,#set key name, it must belong to user authenticated
                'mode': 'CBC',#Set cipher mode
                'pad': pad,
                'iv': iv}#set IV in request

        response = api.encrypt.create(body=data, )#request for encryption
        response = response.body

        #print("Iv: " + iv)

        ciphertext_base64 = response['ciphertext']#get ciphertext
        ciphertext = base64.b64decode(ciphertext_base64)#decode it to bytes

        #print("Ciphertext in base 64: " + ciphertext_base64)

        iv = base64.b64encode(ciphertext[-16:]).decode("utf-8")#//next iv is the last 16 bytes of previous ciphertext as per CBC mode and encode IV to base64
        #print("New Iv: " + iv)

        file_to_encrypt.write(ciphertext)#write it to file

file_to_encrypt.close()

iv = iv_initial #Initialization vector. Required for CBC cypher mode
pad = "none" #Set pad mode to none until the last block

#decrypt
api.add_resource(resource_name="decrypt")
file_to_decrypt=open(File_clear, 'wb')#open file

with open(File_enc, 'rb') as f:

    while 1:
        byte_s = f.read(buff_len)#read file in buff_len blocks until the end of file
        if not byte_s:
            break
        data_base64 = base64.b64encode(byte_s).decode("utf-8")#encode to base64
        #print("Ciphertext in base 64: " + data_base64)
        if len(byte_s) < buff_len:#if block less than buffer, it means end of file and padding should be set PKCS5
            pad = "PKCS5"

        #print("Iv: " + iv)

        data = {'ciphertext': data_base64, #set plain text in request
                'id': KeyName,#set key name, it must belong to user authenticated
                'mode': 'CBC',#Set cipher mode
                'pad': pad,
                'iv': iv}#set IV in request

        response = api.decrypt.create(body=data, )#request for decryption
        response = response.body

        cleartext_base64 = response['plaintext']#get plaintext
        cleartext = base64.b64decode(cleartext_base64)#decode it to bytes

        #print("Plain text in base 64: " + cleartext_base64)

        iv = base64.b64encode(byte_s[-16:]).decode("utf-8")#next iv is the last 16 bytes of previous ciphertext as per CBC mode

        #print("New Iv: " + iv)

        file_to_decrypt.write(cleartext)#write to file