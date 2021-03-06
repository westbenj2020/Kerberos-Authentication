#!/usr/bin/env python3

import socket
import time
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac


HOST = '127.0.0.1'  # The server socket's hostname or IP address
PORT = 65432        # The port used by the server socket
BLOCK_SIZE = 32
client_id = "CIS3319USERID"
a_tg_server_id = "CIS3319TGSID"
std_server_id = "CIS3319SERVERID"
networkAddress = HOST + PORT.__str__()
timestamp1 = time.time()
lifetime2 = 60
lifetime4 = 86400

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # references created server socket
    s.connect((HOST, PORT))  # connects to server socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1:
        s1.connect((HOST, PORT))
        with open('clientKey.txt') as key:
            hmacFile = open('hmacKey.txt')
            hmacKey = hmacFile.read(6)
            std_serverKeyFile = open('std_serverKey.txt')
            std_serverKey = std_serverKeyFile.read(6)
            a_tg_serverKeyFile = open('a_tg_serverKey.txt')
            a_tg_serverKey = a_tg_serverKeyFile.read(6)
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
            print('plain message is: {}'.format(plaintext1))
            cipher1 = DES.new(string1.encode('utf-8'), DES.MODE_ECB)
            data = s.recv(64)  # receives data from server socket - 1024 byte limit
            decryptedData = cipher1.decrypt(data)  # stores decoded byte data as string
            unpad(decryptedData, BLOCK_SIZE)
            decodedData = decryptedData.decode('utf-8').strip()
            print('\n******************')
            print('received ciphertext is: {}'.format(data.decode('utf-8', 'ignore')))  # prints decoded byte data
            print('received plaintext is: {}'.format(decodedData))
            print('******************')
            #  extract tgs ticket to send back to tgs server
            ticketTGS = {decodedData.replace(string1, '').replace(a_tg_serverKey, '').replace(a_tg_server_id, '')
                         .replace(lifetime2.__str__(), '')}
            timestamp2 = ''
            for char in ticketTGS:
                if char.isdigit():
                    timestamp2.__add__(char)
            timestamp3 = time.time()
            authenticatorContents = client_id + networkAddress + timestamp3.__str__()
            authenticatorContentsEncoded = authenticatorContents.encode('utf-8')
            masterKeyCandTGS = string1 + a_tg_serverKey
            cipher2 = DES.new(masterKeyCandTGS.encode('utf-8'), DES.MODE_ECB)
            clientAuthenticator = cipher2.encrypt(pad(authenticatorContentsEncoded, BLOCK_SIZE))
            messageForTGS = std_server_id + ticketTGS.__str__() + clientAuthenticator.__str__()
            messageForTGSEncoded = messageForTGS.encode('utf-8')
            s.sendall(messageForTGSEncoded)  # doesn't need to be encrypted
            cipher3 = DES.new(masterKeyCandTGS.encode('utf-8'), DES.MODE_ECB)
            data1 = s.recv(64)
            decryptedData1 = cipher3.decrypt(data1)
            unpad(decryptedData1, BLOCK_SIZE)
            decodedData1 = decryptedData1.decode('utf-8').strip()
            ticketV = {decodedData1.replace(string1, '').replace(std_serverKey, '').replace(std_server_id, '')}
            timestamp4 = ''
            for char in ticketV:
                if char.isdigit():
                    timestamp4.__add__(char)
            #  whats left of ticketV is ticketV.
            #  create second client authenticator
            timestamp5 = time.time()
            secondAuthenticatorContents = string1 + std_serverKey + client_id + networkAddress + timestamp5.__str__()
            secondAuthenticatorContentsEncoded = secondAuthenticatorContents.encode('utf-8')
            masterKeyCandV = string1 + std_serverKey
            cipher4 = DES.new(masterKeyCandV.encode('utf-8'), DES.MODE_ECB)
            secondClientAuthenticator = cipher4.encrypt(pad(secondAuthenticatorContentsEncoded, BLOCK_SIZE))
            clientTostdServerMessage = ticketV.__str__() + secondClientAuthenticator.__str__()
            #  now send to std server











