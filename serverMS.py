import socket
import json
import sys
from domino import *
import string
import csv
from datetime import datetime
import os
import signal
import threading
import hashlib
import fcntl
import struct
from Crypto import Random as Rand
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA
import base64
from Player import *
import hmac

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography import x509


##################################################################################
# Variaveis

dominoSet = DominoSet()
numDominos = len(dominoSet.getStack())
chain = Chain()
readyCount = 0
nClients = 2 #Número de jogadores
stock = []

bitCommits= []
indexedDominos = []
PseudonymizedDominos = []
indexKeys = []
playersTilesN = []
players_pseudonyms = []

server = socket.gethostbyname('localhost')
port = 5555
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
conn = []
addr = []

tilesPublicKeys = [None]*28

players_list=[] # Lista de pseudonimos
Cheated = False
CheatPlayer = None
points = 0
passCounter = 0
tie = False

#####################################################
### Chave
rand = Rand.new().read
RSAkey = RSA.generate(1024, rand)
public = RSAkey.publickey().exportKey()
private = RSAkey.exportKey()

tmpPub = hashlib.md5(public)
my_hash_public = tmpPub.hexdigest()

##########################################################
## Paddings
##########################################################


def RemovePadding(s):
    return s.replace('`','')


def Padding(s):
    return s + ((16 - len(s) % 16) * '`')


#################################################
### Send and receive functions with Message authentication codes
#################################################

def send(socket,message,key):
    digest = hmac.new(key, message, hashlib.sha1).digest()
    toSend=message +b"::"+digest
    socket.send(toSend)

def receive(socket,size, key):
    message = socket.recv(size)
    msg = message.split(b"::")
    if len(msg) == 1:           
        return msg
    digest= hmac.new(key, msg[0], hashlib.sha1).digest()
    if digest==msg[1]:
        return msg[0]
    else:
        sys.exit("Message authentication failed")


##########################################################
# sessions between players and table
##########################################################
def get_session_server(client,address,i):
    client.send("s00".encode())
    #random 8bytes 
    eightByte = os.urandom(8)
    sess = hashlib.md5(eightByte)
    session = sess.hexdigest()
    #receive player public key
    tmpClientPublic = client.recv(2048)
    client.send("ok".encode())
    #receive player public key hash
    clientPublicHash = client.recv(2048)

    tmpClientPublic = tmpClientPublic.decode('utf-8').replace("\r\n", '') 

    tmpHashObject = hashlib.md5(tmpClientPublic.encode())
    tmpHash = tmpHashObject.hexdigest()

    if tmpHash.encode() == clientPublicHash:
        print("\n[!]Sending 8 bytes to player \n")
        clientPublic = RSA.importKey(tmpClientPublic)
        #send to player session 8B + hash(8B) + hash of server public key encrypted with players public key
        fSend = eightByte + b":" + session.encode() + b":" + my_hash_public.encode()
        fSend = clientPublic.encrypt(fSend, None)
    
        tosend = str(fSend)+"::"+str(public.decode('utf-8'))

        client.send(tosend.encode())  #"sess" in client
        clientPH = client.recv(2048)

        if clientPH != "":
            clientPH = RSA.importKey(private).decrypt(eval(clientPH.decode('utf-8')))
            print("\n[!] Matching session \n")
            if clientPH == eightByte:
                # creating 128 bits AES key
                print("\n[!] Creating AES key\n")
                key_128 = eightByte + eightByte[::-1]
                AESKey = AES.new(key_128, AES.MODE_CBC,IV=key_128)
                clientMsg = AESKey.encrypt(Padding("Ready"))
                #ready signal to client
                send(client,clientMsg,key_128)

                print("\n[!] Waiting for client's pseudonym\n")
                clientPseydonym = receive(client, 2048, key_128).decode('utf-8')
                send(client, "pseudonym ok".encode(), key_128)
                print("\n[!] Client's pseudonym\n")
                print(clientPseydonym)

                print("\n[!] Waiting for client's information about identity\n")
                info = receive(client, 512, key_128).decode()
                
                if info=="noCC":
                    send(client, "ok noCC".encode(), key_128)
                    print("Anonymous player ")
                elif info=="withCC":

                    send(client, "ok withCC".encode(), key_128)
                    #receive signature os pseudonym and public cert of CC
                    sign_ps = receive(client, 16384, key_128).split(b":_:")
                   
                    sign = sign_ps[0]
                    cert_recvd = sign_ps[1]
                    cert = x509.load_pem_x509_certificate(cert_recvd, default_backend())
                    pubKey = cert.public_key()

                    data  = bytes(clientPseydonym, 'utf-8')  
                    try:
                        v = pubKey.verify( sign, data, padding.PKCS1v15(), hashes.SHA1() )
                        #validating signature
                        if v is None:
                            print("\n[!] Valid signature. \n")
                            send(client, "verification successful".encode(), key_128)
                        else:
                            print("\n[!] Invalid signature. \n")
                            send(client, "verification failed".encode(), key_128)
                    except:
                        print("Verification failed")
                        send(client, "verification failed".encode(), key_128) 
                    

                conn.append(client)
                addr.append(address)

                if info=="noCC":
                    #CREATE INSTANCE OF PLAYER and add to server player list
                    player = Player(clientPseydonym,client,tmpClientPublic,clientPublicHash, key_128, points, None)
                else:
                    #CREATE INSTANCE OF PLAYER and add to server player list
                    player = Player(clientPseydonym,client,tmpClientPublic,clientPublicHash, key_128, points, cert_recvd)
                #add to list of connected players                
                players_list.append(player)
                print("\n[!] Player registration completed!\n")

            else:
                print("\nSession key from client does not match")
    else:
        print("\nPublic key and public hash doesn't match")
        client.close()

######################################################################
# session between 2 players
######################################################################
def get_session_player(p1,p2):

    p1.socket.send("s01".encode() )
    p1.socket.recv(256)

    p2.socket.send( "s11".encode() )

    pubk= p2.socket.recv(2048)

    p1.socket.send(pubk)

    msg = p1.socket.recv(32768)

    send(p2.socket, msg, p2.serverKey)

    ok = receive( p2.socket, 1024, p2.serverKey)
    send(p1.socket, ok, p1.serverKey)

    done = receive(p1.socket, 512, p1.serverKey)

    if done.decode() == "DONE":
        
        send(p2.socket, done, p2.serverKey)
        receive(p2.socket, 512, p2.serverKey) 
        send(p2.socket, p1.pseudonym.encode() , p2.serverKey)
        receive(p2.socket, 512, p2.serverKey) 
        send(p1.socket, p2.pseudonym.encode(), p1.serverKey)
        receive(p1.socket, 512, p1.serverKey) 
        return True

    else:
        print("Error in session key")
        return False
######################################################################
# Random Key Pseudonymization
######################################################################
def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

i = 0
for d in dominoSet.getStack():
    d_pips = d.get_pips()
    indexedDominos.append((i, d_pips))
    keyI = get_random_string(16)
    indexKeys.append((i,keyI))
    PseudonymizedDominos.append((i,hash(''+str(i)+keyI+str(d_pips[0])+str(d_pips[1]))))
    i += 1

print("\n[!] Domino set: ",indexedDominos)
#print(indexKeys)
#print(PseudonymizedDominos)
######################################################################
# Iniciar Server
#######################################################################
try:
    s.bind((server, port))
except socket.error as e:
    print(str(e))
s.listen(10)

print("\n [!] Waiting for a connection, Server started\n")

# Conectar aos jogadores
for i in range(0,nClients):
    print("\n [!] Connecting to Player "+str(i))
    x, y = s.accept()

    print("\n [!] Player "+str(i) +" connected on:", y)
    sendMsg = "\n [!] Hello Player "+str(i)
    x.send(str.encode(sendMsg))
    msgRcv = x.recv(2048).decode("utf-8")

    if not msgRcv:
        print("Disconnected :(")
        break
    else:
        print("Sended: ", sendMsg)
        print("Received: ", msgRcv)

    get_session_server(x, y, i)

#get the list of players pseudonyms
for p in players_list:
    players_pseudonyms.append(p.pseudonym)

#send to players pseudonym list
for p in players_list:
    signal = "s20"
    p.socket.send(signal.encode())
    p.socket.recv(256).decode()
    p.socket.send(str(players_pseudonyms).encode())
    p.socket.recv(256).decode()

#create session keys between each pair of players
for p in range(0,nClients):
    for x in range(p+1,nClients):
        get_session_player(players_list[p],players_list[x])

#notify players they can proceed to game
for p in players_list:
    signal="999" #ready
    p.socket.send( signal.encode() ) 


dic = {'dominoSet':PseudonymizedDominos,
    'chain':[], 'tile':[], 'playersReady': False, 'commit': False, 'code': 101, 'player': 0, 'chosenDominos': [], 'nPlayersReady': 0}

for i in range(28):
    dic['chosenDominos'].append('False')

for i in range(0,nClients):
    playersTilesN += [5]

######################################################################
# Send AND Recieve Json
######################################################################

def sendAndRcvDict2(player, dic, key):
	message = str.encode(json.dumps(dic))
	digest = hmac.new(key, message, hashlib.sha1).digest()
	toSend=message +b"::"+digest
	player.socket.send( toSend )  

	message = player.socket.recv(16384)
	msg = message.split(b"::")
	digest= hmac.new(key, msg[0], hashlib.sha1).digest()
	if digest==msg[1]:
		msgRcv = msg[0].decode('utf-8')
		newState = json.loads(msgRcv)
		return newState
	else:
		sys.exit("\n [!] Message authentication failed")


######################################################################
# Stock Encryption By All Players
######################################################################
print('\n [!] Encryption of Stock')
for p in players_list:

    rcvMsg = sendAndRcvDict2(p, dic, p.serverKey)
    if rcvMsg:
        dic['dominoSet'] = rcvMsg['dominoSet']
    else:
        print("\n [!] NO RESPONSE!")


######################################################################
# Check Ready
######################################################################

def checkReady(i, rcvMsg):
    global readyCount #Quando se usa uma variável global na função
    global dic
    global bitCommits
    if rcvMsg['commit']:
        bitCommits.append((i, rcvMsg['bitCommitment']))
        readyCount += 1
    if readyCount == nClients:
        dic['nPlayersReady'] = True
    dic['commit'] = False


#####################################################################
# Tile Distribution and bitCommits
#####################################################################
i = 0
dic['player'] = None
dic['nPlayersReady'] = False

while(not dic['nPlayersReady']):
    dic['code'] = 102
    rcvMsg = sendAndRcvDict2(players_list[i], dic, players_list[i].serverKey)
    srcPlayer = players_pseudonyms[i]
    if 'commit' in rcvMsg:
        checkReady(i, rcvMsg)
    for p in range(0,nClients): #Vê para que jogador tem de enviar a mensagem
        if players_pseudonyms[p] == rcvMsg['player']:
            i = p
    dic['player'] = srcPlayer
    dic['chosenDominos'] = rcvMsg['chosenDominos']
    

######################################################################
# Send bitCommits to Players
######################################################################

for i in range(0, nClients):

    try:
        print("\n [!] Sending bitCommits to Player "+str(i))
        rcvMsg = sendAndRcvDict2(players_list[i], {'bitCommits': bitCommits, 'code': 103},players_list[i].serverKey)

    except Exception as e:
        print(e)
        break

#####################################################################
# Revelation Stage
#####################################################################
i = nClients - 1
revDic = {'chosenDominos': dic['chosenDominos'], 'dominoSet': dic['dominoSet'], 'keys': [], 'code': 104}
for nK in range(nClients * 5):
    revDic['keys'].append([])

while(i >= 0):
    try:
        print("\n [!] Sending the Array and chosenIndexes to Player "+str(i))
        revDic['code'] = 104
        rcvMsg = sendAndRcvDict2(players_list[i], revDic,players_list[i].serverKey)
        if 'keys' in rcvMsg:
            revDic['keys'] = rcvMsg['keys']
            #print("Current Keys:", revDic['keys'])

        # Player Decryption
        for p in range(0, nClients):
            rcvMsg = sendAndRcvDict2(players_list[p], {'chosenDominos': dic['chosenDominos'], 'dominoSet': dic['dominoSet'],'keys': revDic['keys'], 'code': 105},players_list[p].serverKey)
            dic['dominoSet'] = rcvMsg['dominoSet']
            revDic['dominoSet'] = dic['dominoSet']
            

        revDic['keys'] = []
        for nK in range(nClients * 5):
            revDic['keys'].append([])



    except Exception as e:
        print(e)
        break

    i = (i-1)

stock = [t for t in dic['dominoSet'] if ',' not in t]
print('\n [!] Stock: ', stock)

#####################################################################
# 6. Tile de-anonymization preparation stage
#####################################################################

#Faz passar a stack com as public keys de cada jogador até todos estarem prontos
i = 0
dic['code'] = 66
dic['nPlayersReady'] = False
dic['publicKeys'] = ['None'] * 28
print("\n [!] Asking players for theirs tile's public keys")

dic['code'] = 66 #O primeiro código é o 66 e os seguintes são o 10

while(not dic['nPlayersReady']):
    dic = sendAndRcvDict2(players_list[i], dic, players_list[i].serverKey)
    srcPlayer = players_pseudonyms[i]
    dic['code'] = 10
    for p in range(0,nClients): #Vê para que jogador tem de enviar a mensagem
        if players_pseudonyms[p] == dic['player']:
            i = p
    dic['player'] = srcPlayer


cont= 0
for k in range(len(dic['publicKeys'])):
    if dic['publicKeys'][k] != 'None':
        cont+=1
        tilesPublicKeys[k] = base64.b64decode(dic['publicKeys'][k])

#print("Public Keys: ",tilesPublicKeys)


#####################################################################
# 7. Tile de-anonymization stage
#####################################################################

dic['dominoSet'] = []
dic['publicKeys'] = []
cont=0
i=0
for k in tilesPublicKeys:
    if k:
        tile = indexedDominos[cont][1]

        public_key = serialization.load_pem_public_key(
            k,
            backend=default_backend()
        )
        encryptedTile = public_key.encrypt(
            tile,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    else:
        encryptedTile = None
    if encryptedTile:
        encryptedTile = base64.b64encode(encryptedTile).decode('ascii')
    dic['dominoSet'].append(encryptedTile)

    cont+=1

dic['code'] = 67
for i in range(0, nClients):

    print("\n [!] Sending encrypted tiles to Player "+str(i))
    rcvMsg = sendAndRcvDict2(players_list[i], dic, players_list[i].serverKey)


######################################################################
# Ask Players if the turn is valid
######################################################################

def verifyPlayers4Play(i, playedDomino):
    code = 0 #Variavel que informa o jogador que a peça é válida

    #O server verifica se a jogada é válida
    if chain.isEmpty(): 
        print("\n [!] Valid tile.")
    elif (chain.is_playable(playedDomino)):
        print("\n [!] Valid tile.")
    else:
        print("\n [!] Invalid tile!")
        code = 1

    #Se achar que é válida, o server pergunta a cada jogador se concorda com a jogada.
    #Caso um jogador não concorde, a jogada torna-se inválida. (MELHORAR!!)
    if (code == 0):
        for p in range(nClients):
            dic['code'] = 3
            dic['tile'] = playedDomino.get_pips()
            dic['player'] = i
            if p != i:
                responseDic = sendAndRcvDict2(players_list[p], dic,players_list[p].serverKey)
                if responseDic['code'] == 4:
                    print("\n [!] Player "+str(p)+" accepted the play.")
                elif responseDic['code'] == 5:
                    print("\n [!] Player "+str(p)+" did not accept the play.")
                    code = 1000
                    dic['code']=code
                    for x in range(nClients):
                        #sendAndRcvDict2(players_list[x], dic, players_list[x].serverKey)
                        #send(players_list[x].socket, dic, players_list[x].serverKey)
                        #receive(n.socket, 256, n.serverKey)
                        sendAndRcvDict2(players_list[x], dic, players_list[x].serverKey)
                    sys.exit("Game Over. Cheating acusation.")
                    #break
                  
    if code == 0:
        if chain.isEmpty():
          
            chain.start(playedDomino)
            
        else:    
           
            chain.add(playedDomino)
        playersTilesN[i] -= 1


    dic['chain']=chain.getList()
    dic['code']=code
    print("\n [!] Current chain:", chain)
    sendAndRcvDict2(players_list[i], dic, players_list[i].serverKey)

    return code

######################################################################
def set_points(i):
    index = 0
    p = None
    for pos in players_list:
        if index == i:
            p = pos
            p.set_points()
        index = index + 1
    points = str(p.show_points()) 
    print("\n[!] SETING WINNER POINTS = ", p.show_points())
    return

######################################################################
### Save game info to a file
######################################################################
def accounting(info, signature):

    toWrite = info +b":_:" + signature

    game_info = json.loads(info.decode())

    #################################
    
    # Create a directory if not exists
    path = os.getcwd()+'/accounting/'

    if not os.path.isdir(path):
        os.mkdir(path)
    
    date = None
    #Geting the time and day of the game
    for key in game_info["Game"]:
        if key["Date"]:
            date = key["Date"]

    file = date
    # Writing the json on file and saving it

    with open(path+file+".txt","wb") as outfile:
        outfile.write(toWrite)
        outfile.close()

    return None

######################################################################
# Ask Players if the turn is valid
######################################################################

def verifyIfPlayerWon(i): #COMPLETAR
    return playersTilesN[i] == 0

#####################################################################
# Jogadas
#####################################################################
dic['playersReady'] = True
dic['code'] = 0
dic = {'code': dic['code'], 'playersReady': dic['playersReady'], 'chain': dic['chain']}
i = 0
i106 = nClients - 1
i107 = 0
stockClient = None

while True:
    if dic['playersReady']:
        print("\n [!] Player "+str(i)+" turn.")
        responseDic = sendAndRcvDict2(players_list[i], dic, players_list[i].serverKey)
        code = responseDic['code']

        #####################################################
        # STOCK ACCESS PROCESS
        #####################################################
        if code == 6: #Server receber o pedido da stock
            print("\n [!] Stock access ")
            dic['code'] = 106
            dic['stock'] = stock
            stockClient = i
            i106 = nClients - 1
            #print('\n [!] Stock Take: ', dic)     

        elif code == 106:
            stock = responseDic['stock']
            print('\n    [!] Redo Revelation - Tile: ', responseDic['tileS'])
            dic['tileS'] = responseDic['tileS']
            dic['code'] = 107
            dic['keys'] = []
            i = i106

        elif code == 107:
            if responseDic['keys'] != [] and i107 != nClients:
                dic['tileS'] = responseDic['tileS']
                i = i107
                i107 += 1
                dic['keys'] = responseDic['keys']
                #print('Keys ', dic['keys'])
            elif i107 == nClients and i106 != 0:
                dic['tileS'] = responseDic['tileS']
                i107 = 0
                i106 -= 1
                i = i106
                dic['keys'] = []
            else:
                if stockClient == i:
                    dic['tileS'] = responseDic['tileS']
                dic['code'] = 108
                dic['StockKey'] = '' 

        elif code==108:
            print('\n    [!] REDO de-anonymization')
            i = stockClient
            if responseDic['StockKey'] != '':
                dic['StockKey'] = responseDic['StockKey']
                index = dic['tileS'].split(',')[0][1:]
                tile = indexedDominos[int(index)][1]
                key = base64.b64decode(dic['StockKey'])
                public_key = serialization.load_pem_public_key(
                    key,
                    backend=default_backend()
                )
                encryptedTile = public_key.encrypt(
                    tile,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encryptedTile = base64.b64encode(encryptedTile).decode('ascii')
                dic['tileS']= encryptedTile
                dic['code'] = 109

        elif code==109:
            playersTilesN[i] += 1
            dic['code'] = 0
            dic['StockKey'] = ''
            dic['tileS'] = ''
            dic['keys'] = []
            i106 = nClients - 1
            i107 = 0
            stockClient = None
        

        elif code != 2:
            playedDomino = Domino(responseDic['tile'][0], responseDic['tile'][1])
            print("\n [!] Player "+str(i)+" played "+str(playedDomino))
            code2 = verifyPlayers4Play(i, playedDomino)
            #print("\n [!] Player "+str(i)+" number of Tiles: " + str(playersTilesN[i]))
            if code2 == 0 and code == 200: #Jogada foi validada pelos jogadores e o jogador diz que ganhou
                if verifyIfPlayerWon(i):
                    break
            code = code2

        elif code == 2:
            passCounter += 1
            print("\n [!] Player "+str(i)+" passed.")
            if passCounter == nClients:
                tie = True
                break
            
        if (code != 1 and code != 6 and code != 7 and code != 8 and code!=106 and code!=107 and code!=108 and code!=109): #Não avança para o proximo jogador se a peça jogada foi inválida ou quando o jogador pede e devolve a stock

            i = (i+1)%nClients

#####################################################################################
def checkBitCommitments():
    dic['code'] = 205
    print("\n [!] CHECKING BIT COMMITMENTS!")
    for p in range(0,nClients):
        dic['BCdata'] = []
        dic['BCcheck'] = True
        respDic = sendAndRcvDict2(players_list[p], dic, players_list[p].serverKey)
        dic['BCdata'] = respDic['BCdata']
        for pi in range(0, nClients):
            respDic2 = sendAndRcvDict2(players_list[pi], dic, players_list[pi].serverKey)
            if not respDic2['BCcheck']:
                Cheated = True
                CheatPlayer = p
                break
#####################################################################################


checkBitCommitments()

if not Cheated:
    print("\n [!] Game was clean")
    for p in range(0,nClients): #Informa jogadores de quem ganhou
        if tie:
            dic['code'] = 203
        else:
            dic['code'] = 201
            if p == i:
                dic['code'] = 202
            dic['player'] = i
        resposta = sendAndRcvDict2(players_list[p], dic, players_list[p].serverKey)

    p = players_list[i]
    if tie:
        print("\n [!] Tie.")
    else:
        print("[!] Player "+str(i)+" has won the game")
        set_points(i)
        now = datetime.now()    
        current_time = now.strftime("%H:%M:%S")
        today = now.strftime("%b-%d-%Y")
        info = {"Game": []}

        for idx in range(0,nClients):
            info["Game"].append( {"Date": str(today)+"_"+str(current_time),"Player": str(players_list[idx].pseudonym), "Points":str(players_list[idx].points)})
            game_info = json.dumps(info)
        
        game_hash = hashlib.md5(game_info.encode()).hexdigest()
        
        if resposta:
            if players_list[i].cert is not None:
                print("[!] Sending game info to the winner") 

                send(players_list[i].socket, str(game_info).encode(), players_list[i].serverKey)

                print("    [!] Game info sent complete!") 
                signature_ps = receive(players_list[i].socket, 1024, players_list[i].serverKey)

                # Verificar assinatura do pseudonimo
                certif = players_list[i].cert
                cert = x509.load_pem_x509_certificate(certif, default_backend())
                pubKey = cert.public_key()
                data  = bytes(players_list[i].pseudonym, 'utf-8')  
                try:
                    v = pubKey.verify( signature_ps, data, padding.PKCS1v15(), hashes.SHA1() )
                    if v is None:
                        
                        send(players_list[i].socket, "checked".encode(), players_list[i].serverKey)

                        clientGameSign = receive(players_list[i].socket, 16384, players_list[i].serverKey)
                       
                        clientGameSign = clientGameSign.split(b":__:")
                        
                        game_info_client = clientGameSign[0]
                        
                        game_hash2= hashlib.md5(game_info_client).hexdigest()
                        if game_hash != game_hash2:
                            print("\n[!] Game information has been changed!")
                        
                        game_sign = clientGameSign[1]
                        #guardar no ficheiro game_info_client + game_sign
                        print("\n[!] POINTS READY TO WRITE ON FILE!")
                        
                        # ENVIAR O JSON DO JOGO (VERIFICAR SE ESTA COMO JSON, ENVIAR A SINATURA)
                        accounting(game_info_client,game_sign)
                        print("\n[!] POINTS WRITTEN !")

                except Exception as e:
                    print("\n [!] Verification failed")
                    print(e)
                    send(players_list[i].socket, "not checked".encode(), players_list[i].serverKey) 
            else:
                print("\n[!] Player "+str(i)+" win " + str(p.show_points()) + " points")
                print("\n[!] No CC match for the winner")

                send(players_list[i].socket, 'not_cc'.encode(), players_list[i].serverKey)

                print("    [!] Points not atributed")
                print("        [!] Ending the game!") 

                               
    
else:
    print("\n [!] Player "+str(i)+ " CHEATED!")



print("\n[!] Game Over")
#############################################################################################################
'''
Code:
0-Tile válida
1-Tile inválida
2-Pass
3-Jogador jogou a tile x
4-Jogador aceita a jogada do outro jogador
5-Jogador reclama batota da jogada do outro jogador
6-Jogador pede a stock
7-Jogador devolve a stock depois de retirar uma peça
8-Server aceitou o estado da stock
10-Player wants to send a message to other player
66 - Server envia a lista publicKeys para os jogadores
     preencherem com as chaves públicas de cada peça
67 - Server envia as peças encriptadas com a respetiva chave pública
101 - Stock Encryption
102 - TIle Select and Bit Commitments
103 - Bit COMMITS STORAGE
104 - Revelation Stage
105 - Hand Decryptions
106_109 - Stock access
200 - Player claims he won
201 - Server tells players that player x has won
202 - Server tells player he has won
203 - Server tells players that there was a tie
205 - Check Bit Commitments
s00 - set session player-table
999 - sessions ready
s20 - sending list of pseudonyms
s01_s11 - players setting session between them
'''

