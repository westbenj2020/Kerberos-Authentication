#!/usr/bin/env python3

import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
import time

HOST = '127.0.0.1'  # IP address for server socket
PORT = 65432  # port for server socket
networkAddress = HOST + PORT.__str__()
BLOCK_SIZE = 64
client_id = "CIS3319USERID"
a_tg_server_id = "CIS3319TGSID"
std_server_id = "CIS3319SERVERID"
lifetime2 = 60
lifetime4 = 86400


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1:  # creates server socket
    s1.bind((HOST, PORT))  # binds server socket to address
    s1.listen()  # enables server socket to accept attempted connection from client socket
    print('\nServer is running...')
    print('\nAccepted new connection from "{}"...'.format(HOST))
    client, addr = s1.accept()  # accepts connection - returns new socket object and address bound to client socket
    with client:
        hmacFile = open('hmacKey.txt')
        hmacKey = hmacFile.read(8)
        std_serverKeyFile = open('std_serverKey.txt')
        std_serverKey = std_serverKeyFile.read(8)
        a_tg_serverKeyFile = open('a_tg_serverKey.txt')
        a_tg_serverKey = a_tg_serverKeyFile.read(8)
        with open('clientKey.txt') as key:  # encrypt message to be sent back using Client key
            string = key.read(8)
            string1 = string
            cipher = DES.new(string.encode('utf-8'), DES.MODE_ECB)
            data = client.recv(1024)
            decryptedData = cipher.decrypt(data)  # stores decoded byte data as string
            unpad(decryptedData, BLOCK_SIZE)
            decodedData = decryptedData.decode('utf-8').strip()
            masterKeyCandV = string1[0:4] + std_serverKey[-4:]
            #  extract ts5 from client authenticator
            timestamp5 = decodedData[-10:]
            timestamp5asint = int(timestamp5)
            currentUnixTime = time.time()
            print('Received message from client: {}'.format(decodedData))
            if currentUnixTime - timestamp5asint < lifetime4:
                print('Ticket V is valid.')
                timestampNewasint = timestamp5asint + 1
                newTimestamp = str(timestamp5asint)
                cipher1 = DES.new(masterKeyCandV.encode('utf-8'), DES.MODE_ECB)
                mutualAuthMessage = cipher1.encrypt(pad(newTimestamp.encode('utf-8'), BLOCK_SIZE))
                client.sendall(mutualAuthMessage)
            else:
                print('Ticket V is invalid.')

        





