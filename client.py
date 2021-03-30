#!/usr/bin/env python3

import socket
import time
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac


HOST = '127.0.0.1'  # The server socket's hostname or IP address
PORT = 65432        # The port used by the server socket
PORT1 = 80
BLOCK_SIZE = 64
client_id = "CIS3319USERID"
a_tg_server_id = "CIS3319TGSID"
std_server_id = "CIS3319SERVERID"
networkAddress = HOST + PORT.__str__()
timestamp1 = time.time()
lifetime2 = 60
lifetime4 = 86400

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # references created server socket
    s.connect((HOST, PORT))  # connects to server socket
    with open('clientKey.txt') as key:
        hmacFile = open('hmacKey.txt')
        hmacKey = hmacFile.read(8)
        std_serverKeyFile = open('std_serverKey.txt')
        std_serverKey = std_serverKeyFile.read(8)
        a_tg_serverKeyFile = open('a_tg_serverKey.txt')
        a_tg_serverKey = a_tg_serverKeyFile.read(8)
        string = key.read(8)
        string1 = string
        #  cipher = DES.new(string.encode('utf-8'), DES.MODE_ECB)
        plaintext1 = client_id + a_tg_server_id + timestamp1.__str__()  # retrieves plaintext input from user
        plaintext1Encoded = plaintext1.encode('utf-8')
        #  msgAuth = hmac.new(hmacKey, plaintext1, hashlib.sha256)
        #  stringer = msgAuth.hexdigest()
        #  msgWithHMAC = stringer + plaintext1.decode()
        #  msgWithHMACEncoded = msgWithHMAC.encode('utf-8')
        #  msg = cipher.encrypt(pad(msgWithHMACEncoded, BLOCK_SIZE))  # encrypts plaintext
        s.sendall(plaintext1Encoded)  # sends encrypted message to server
        #  print('plain message is: {}'.format(plaintext1))
        cipher1 = DES.new(string1.encode('utf-8'), DES.MODE_ECB)
        data = s.recv(1024)  # receives data from server socket - 1024 byte limit
        decryptedData = cipher1.decrypt(data)  # stores decoded byte data as string
        unpaddedData = unpad(decryptedData, BLOCK_SIZE)
        decodedData = unpaddedData.decode('utf-8')
        ticketTGS = string1 + a_tg_serverKey + client_id + networkAddress + a_tg_server_id + decodedData[28:40]
        print('\n******************')
        #  print('received ciphertext is: {}'.format(data.decode('utf-8', 'ignore')))  # prints decoded byte data
        print('received plaintext from authentication server: {}'.format(decodedData[0:40].strip()))
        #  extract tgs ticket to send back to tgs server
        print('received ticket from authentication server: {}'.format(ticketTGS).strip())
        print('*******************')
        timestamp3 = time.time().__trunc__()
        authenticatorContents = client_id + networkAddress + timestamp3.__str__()
        authenticatorContentsEncoded = authenticatorContents.encode('utf-8')
        masterKeyCandTGS = string1[0:4] + a_tg_serverKey[-4:]
        cipher2 = DES.new(masterKeyCandTGS.encode('utf-8'), DES.MODE_ECB)
        clientAuthenticator = cipher2.encrypt(pad(authenticatorContentsEncoded, BLOCK_SIZE))
        #  print(clientAuthenticator)
        messageForTGS = std_server_id + ticketTGS.__str__() + clientAuthenticator.__str__()
        messageForTGSEncoded = messageForTGS.encode('utf-8')
        s.sendall(messageForTGSEncoded)  # doesn't need to be encrypted
        cipher3 = DES.new(masterKeyCandTGS.encode('utf-8'), DES.MODE_ECB)
        data1 = s.recv(1024)
        decryptedData1 = cipher3.decrypt(data1)
        unpaddedData1 = unpad(decryptedData1, BLOCK_SIZE)
        decodedData1 = unpaddedData1.decode('utf-8').strip()
        timestamp4 = decodedData1[31:41]
        nonencryptedticketV = string1 + std_serverKey + client_id + networkAddress + std_server_id + \
            timestamp4.__str__() + lifetime4.__str__()
        nonencryptedticketVEncoded = nonencryptedticketV.encode('utf-8')
        cipher2 = DES.new(std_serverKey.encode('utf-8'), DES.MODE_ECB)
        encryptedticketV = cipher2.encrypt(pad(nonencryptedticketVEncoded, BLOCK_SIZE))
        print('\nReceived plaintext from ticket-granting server: {}'.format(decodedData1))
        print('\nReceived Ticket V from ticket-granting server: {}\n'.format(nonencryptedticketV))
        key.close()
        s.close()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1:
    s1.connect((HOST, PORT1))
    #  whats left of ticketV is ticketV.
    #  create second client authenticator
    timestamp5 = time.time().__trunc__()
    timestamp5PlusOne = timestamp5 + 1
    secondAuthenticatorContents = string1 + std_serverKey + client_id + networkAddress + timestamp5.__str__()
    secondAuthenticatorContentsEncoded = secondAuthenticatorContents.encode('utf-8')
    masterKeyCandV = string1[0:4] + std_serverKey[-4:]
    cipher4 = DES.new(masterKeyCandV.encode('utf-8'), DES.MODE_ECB)
    secondClientAuthenticator = cipher4.encrypt(pad(secondAuthenticatorContentsEncoded, BLOCK_SIZE))
    clientTostdServerMessage = encryptedticketV.__str__() + secondClientAuthenticator.__str__()
    s1.sendall(clientTostdServerMessage.encode('utf-8'))
    cipher5 = DES.new(masterKeyCandV.encode('utf-8'), DES.MODE_ECB)
    data2 = s1.recv(1024)
    decryptedData2 = cipher5.decrypt(data2)
    unpad(decryptedData2, BLOCK_SIZE)
    decodedData2 = decryptedData2.decode('utf-8').strip()
    print('Received message from Server V: {}'.format(decodedData2))
    if decodedData2 == timestamp5PlusOne:
        print('Server V is validated.')
    else:
        print('Server V could not be validated.')















