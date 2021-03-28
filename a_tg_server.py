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
BLOCK_SIZE = 32
client_id = "CIS3319USERID"
a_tg_server_id = "CIS3319TGSID"
std_server_id = "CIS3319SERVERID"
lifetime2 = 60
lifetime4 = 86400


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # creates server socket
    s.bind((HOST, PORT))  # binds server socket to address
    s.listen()  # enables server socket to accept attempted connection from client socket
    print('\nServer is running...')
    print('\nAccepted new connection from "{}"...'.format(HOST))
    client, addr = s.accept()  # accepts connection - returns new socket object and address bound to client socket
    with client:
        hmacFile = open('hmacKey.txt')
        hmacKey = hmacFile.read(6)
        std_serverKeyFile = open('std_serverKey.txt')
        std_serverKey = std_serverKeyFile.read(6)
        a_tg_serverKeyFile = open('a_tg_serverKey.txt')
        a_tg_serverKey = a_tg_serverKeyFile.read(6)
        with open('clientKey.txt') as key:  # encrypt message to be sent back using Client key
            string = key.read(8)
            string1 = string
            cipher = DES.new(string.encode('utf-8'), DES.MODE_ECB)
            data = client.recv(64)
            timestamp2 = time.time()
            #  receivedMsg = cipher.decrypt(data)
            #  unpad(receivedMsg, BLOCK_SIZE)
            decodedMsg = data.decode('utf-8').strip()
            #  print('received ciphertext is: {}'.format(data.decode('utf-8', 'ignore')))
            print('received message from client: '.format(decodedMsg))
            #  print('******************')
            nonencryptedticketTGS = string1 + a_tg_serverKey + client_id + networkAddress + a_tg_server_id +\
                timestamp2.__str__() + lifetime2.__str__()
            nonencryptedticketTGSEncoded = nonencryptedticketTGS.encode('utf-8')
            atgsCipher = DES.new(a_tg_serverKey.encode('utf-8'), DES.MODE_ECB)
            encryptedticketTGSEncoded = atgsCipher.encrypt(pad(nonencryptedticketTGSEncoded, BLOCK_SIZE))
            plaintext1 = string1 + a_tg_serverKey + a_tg_server_id + timestamp2.__str__() +\
                lifetime2.__str__() + encryptedticketTGSEncoded.__str__()
            print('\nHi, this is server.')
            print('******************')
            plaintext1Encoded = plaintext1.encode('utf-8')
            cipher1 = DES.new(string1.encode('utf-8'), DES.MODE_ECB)
            msg = cipher1.encrypt(pad(plaintext1Encoded, BLOCK_SIZE))
            #  print('key is: "{}"'.format(string1))
            client.sendall(msg)  # sends encrypted message to server
            #  print('Sent plaintext is: {}'.format(plaintext1))
            #  print('Sent ciphertext is: {}'.format(msg.decode('utf-8', 'ignore')))
            print('******************')
            receivedData = client.recv(64) #  might need to make larger input size and just split to rid of space
            receivedDataDecoded = receivedData.decode('utf-8')
            ticketAndAuthenticatorData = {receivedDataDecoded.replace(std_server_id, '')}
            masterKeyCandTGS = string1 + a_tg_serverKey
            cipherTicketTGS = DES.new(a_tg_serverKey.encode('utf-8'), DES.MODE_ECB)
            cipherAuthenticator = DES.new(masterKeyCandTGS.encode('utf-8'), DES.MODE_ECB)
            decryptedTicketAndAuthenticator = cipherTicketTGS.decrypt(ticketAndAuthenticatorData.__str__().
                                                                      encode('utf-8'))
            decodedTicketAndAuthenticator = decryptedTicketAndAuthenticator.decode('utf-8')
            truncTicketTGS = {decodedTicketAndAuthenticator.replace(masterKeyCandTGS, '').replace(client_id, '').
                              replace(networkAddress, '').replace(a_tg_server_id, '')}
            ticketTS = truncTicketTGS[0:10]
            convTicket = ticketTS.__str__()
            ticketTSAsInt = int(convTicket)
            currentUnixTime = time.time()
            if currentUnixTime - ticketTSAsInt < lifetime2:
                print('TGS ticket is valid.')
                timestamp4 = time.time()
                nonencryptedticketV = string1 + std_serverKey + client_id + networkAddress + std_server_id + \
                    timestamp4.__str__() + lifetime4.__str__()
                nonencryptedticketVEncoded = nonencryptedticketV.encode('utf-8')
                cipher2 = DES.new(std_serverKey.encode('utf-8'), DES.MODE_ECB)
                encryptedticketV = cipher2.encrypt(pad(nonencryptedticketVEncoded, BLOCK_SIZE))
                plaintext2 = string1 + std_serverKey + std_server_id + timestamp4.__str__() + encryptedticketV.__str__()
                plaintext2Encoded = plaintext2.encode('utf-8')
                cipher3 = DES.new(masterKeyCandTGS.encode('utf-8'), DES.MODE_ECB)
                messageForClient = cipher3.encrypt(pad(plaintext2Encoded, BLOCK_SIZE))
                client.sendall(messageForClient)
            else:
                print('Invalid TGS ticket.')


