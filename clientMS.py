from networkMS import Network
import json
from domino import *
import hmac
import string
import random
import base64
import sys
import socket
import os
import hashlib
import signal
import secrets

from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import  MD5
from Crypto import Random as Rand
from Crypto.PublicKey import RSA

import cryptography
from cryptography.hazmat.primitives.ciphers import algorithms,modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from PyKCS11 import *
from PyKCS11.LowLevel import *
from cryptography.hazmat.primitives.serialization import load_der_public_key,Encoding
from cryptography.hazmat.primitives.asymmetric import (padding, rsa, utils )
from cryptography import x509

n = Network()
print(n.stack.pop())
print(n.send("Hello!"))
run = True

isAI = True
if (len(sys.argv)>1) and (sys.argv[1] == 'm'):
    isAI = False
    print('You control the player!')
else:
    print('The player will be controlled by the computer.')

initialHand = []
decryptedHand = []
hand = []
stack = []
chain = []
keysUsed = []
ready = 0
choices = 0
bitCommits = []

myTilesIndexes = []
myTilesPseud = []
myTilesKeys = []
keyCount = 0
continua = True
tileStock = None
pubKStock = ''
privKStock = ''   


players_sess_keys=[]        #contains tuples with other client pseudonym and AES key

mypseudonym = secrets.token_hex(16)
global no_identity
no_identity = True   #True - player is anonymous, False - pseudonym owned by an identity

######################################################
#### Geração chaves

def generateAK():
    rand = Rand.new().read
    global RSAkey
    RSAkey = RSA.generate(1024, rand)
    public = RSAkey.publickey().exportKey()
    private = RSAkey.exportKey()
    return (public, private)

def generateAK2():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return (public_key, private_key)
######################################################
### Sign pseudonym and return certificate for server validate sugnature
def signPseudonym():
    try:
        lib = '/usr/local/lib/libpteidpkcs11.so'

        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load( lib )
        slots= pkcs11.getSlotList()

        for slot in slots:
            if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo( slot ).label:
                data = bytes(mypseudonym, 'utf-8')            
                session = pkcs11.openSession( slot )

                privKey= session.findObjects( [(CKA_CLASS, CKO_PRIVATE_KEY),
                                            ( CKA_LABEL,'CITIZEN AUTHENTICATION KEY')] )[0]
                pseudonym_signature = bytes(session.sign(privKey, data, Mechanism(CKM_SHA1_RSA_PKCS)))

                info = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), 
                    (PyKCS11.CKA_LABEL,  "CITIZEN AUTHENTICATION CERTIFICATE")])

                der = bytes([c.to_dict()['CKA_VALUE'] for c in info][0])
    
                cert = x509.load_der_x509_certificate(der, default_backend()).public_bytes(Encoding.PEM)

                global no_identity
                no_identity = False        

                session.closeSession()
                return pseudonym_signature, cert
    except Exception as e:
        print(e)

        print("Impossible to sign pseudonym")
        return None , None

tup = generateAK()
public = tup[0]
private = tup[1]

tmpPub = hashlib.md5(public)
my_hash_public = tmpPub.hexdigest()

#####################################################
### Paddings
#####################################################

def RemovePadding(s):
    return s.replace('`','')


def Padding(s):
    return s + ((16 - len(s) % 16) * '`')

#####################################################
### Send and Receive functions with message authentication codes
#####################################################
def send(socket,message,key):
    digest = hmac.new(key, message, hashlib.sha1).digest()
    toSend=message +b"::"+digest
    socket.send2(toSend)


def receive(socket,size, key):
    message = socket.recv2(size)

    msg = message.split(b"::")
    if len(msg) != 2:
        return message
    digest= hmac.new(key, msg[0], hashlib.sha1).digest()
    if digest==msg[1]:
        return msg[0]
    else:
        sys.exit("Message authentication failed")

######################################################################
## sign pseudonym for server validation with cert that it obtained before and sign game data to save to file
######################################################################
def sign_pseudonym_and_game(game):
    try:
        lib = '/usr/local/lib/libpteidpkcs11.so'

        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load( lib )
        slots= pkcs11.getSlotList()

        for slot in slots:
            if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo( slot ).label:
                data = bytes(mypseudonym, 'utf-8')
                data2 =  json.dumps(game).encode('utf-8') 
                session = pkcs11.openSession( slot )
                

                privKey= session.findObjects( [(CKA_CLASS, CKO_PRIVATE_KEY),
                                            ( CKA_LABEL,'CITIZEN AUTHENTICATION KEY')] )[0]
                pseudonym_signature = bytes(session.sign(privKey, data, Mechanism(CKM_SHA1_RSA_PKCS)))

                game_signature = bytes(session.sign(privKey, data2 , Mechanism(CKM_SHA1_RSA_PKCS)))

                session.closeSession()

                return pseudonym_signature, game_signature
    except:
   
        print("Impossible to sign pseudonym and game data")
        return None , None

    

######################################################################
# Check if winner points match on the document sent by server        
#####################################################################
def check_points_match(points, winner_points, pseudonym, game):
    
    # return signatures of pseudobym and game data
    sign_ps, sign_game = sign_pseudonym_and_game(game) 
    send(n,sign_ps,server_session_key)
    check = receive(n, 512, server_session_key).decode()

    if check == 'checked':
        if int(points) == winner_points:
            toSend = json.dumps(game).encode() + b":__:" + sign_game 
            send(n, toSend, server_session_key)

            return True
        else:

            return False

    elif check == 'not checked':
        return False

#####################################################################

server_sess_flag = False

#first loop to set sessions
while True:
    msg = n.recv()
    if msg == "s00":
        #send public key to server
        n.send2(public)
        n.recv2(512).decode('utf-8')
        #send hash of public key to server
        n.send2(my_hash_public.encode())

        sess_8b = n.recv2(4072)

        split = sess_8b.split(b"::")
        toDecrypt = split[0]
        serverPublic = split[1]
        decrypted = RSA.importKey(private).decrypt(eval(toDecrypt.decode('ascii').replace("\r\r\n", '')))

        splittedDecrypt = decrypted.split(b":")
        eightByte = splittedDecrypt[0]
        hashOfEight = splittedDecrypt[1]
        hashOfSPublic = splittedDecrypt[2]

        # hashing for checking
        sess = hashlib.md5(eightByte)
        session = sess.hexdigest()

        hashObj = hashlib.md5(serverPublic.decode('utf-8').replace('\r\n','').encode() )
        server_public_hash = hashObj.hexdigest()
        print("\n[!] Matching server's public key & eight byte \n")
        if server_public_hash == hashOfSPublic.decode('ascii') and session == hashOfEight.decode('ascii'):
            # encrypt back the eight byte key with the server public key and send it
            print("\n[!] Sending encrypted session \n")

            serverPub = RSA.importKey(serverPublic)
            
            sess = serverPub.encrypt(eightByte, None)

            n.send2(str(sess).encode()) #clientPH in server
            print("\n[!] Creating AES key\n")
            key_128 = eightByte + eightByte[::-1]
            AESKey = AES.new(key_128, AES.MODE_CBC,IV=key_128)
            global server_session_key 
            server_session_key = key_128
            #flag to indicate that exists session key with server
            server_sess_flag = True
            # receiving ready from server
            serverMsg = receive( n , 2048, key_128)
            serverMsg = RemovePadding(AESKey.decrypt(serverMsg).decode('ascii'))

            if serverMsg == "Ready":
                print("\n[!] Server is ready to communicate\n")
                serverMsg = mypseudonym
                send(n, serverMsg.encode(), server_session_key)
                receive(n, 512, server_session_key)


                while True:
                    sign, cert = signPseudonym()
                   
                    if no_identity:
                        val = input("\n[?]Continue without CC? 'yes' or 'no' to try again \n ") 
                        if val == 'yes':
                            print("\n[!]Continues without CC...")
                            break
                        elif val == 'no':
                            print("Trying again...")
                    elif not no_identity:
                        break

                if no_identity:
                    send(n, "noCC".encode(), server_session_key)
                    receive(n, 512, server_session_key)
                   
                elif not no_identity:
                    send(n, "withCC".encode(), server_session_key)
                    receive(n, 512, server_session_key)
                    

                    toServer = sign + b":_:" + cert

                    send(n,toServer,server_session_key)
                    receive(n, 512, server_session_key)
    
    #receiving list of all pseudonyms
    elif msg == "s20":
        n.send2("s20 ok".encode())
        global players_list
        players_list = n.recv()
        players_list = players_list.replace("'","").replace("[","").replace("]","").split(", ")
        n.send2("players received".encode())

    elif msg == "s01":
        n.send2("processing s01".encode())

        pubk = n.recv2(2048)

        eightByte = os.urandom(8)
        digest = MD5.new(eightByte).digest()

        signature = json.dumps( RSAkey.sign(digest,"") )

        toSend = eightByte 

        cipher = PKCS1_OAEP.new(RSA.importKey(pubk))
        toSend = cipher.encrypt(toSend)

        toSend = toSend + b"::" + signature.encode() + b"::" + RSAkey.publickey().exportKey()

        key_128 = eightByte + eightByte[::-1]

        n.send2(toSend)
        ok = receive(n, 1024, server_session_key)
        
        AESKey = AES.new(key_128, AES.MODE_CBC,IV=key_128)
        ok2 = RemovePadding(AESKey.decrypt(ok).decode('ascii'))

        if ok2 == "OK":
            
            send(n, "DONE".encode(), server_session_key)
            other_pseud = receive(n, 2048, server_session_key).decode()
            send(n, "pseud done".encode(), server_session_key)
            
            players_sess_keys.append([other_pseud,key_128])

    elif msg == "s11":

        n.send2(RSAkey.publickey().exportKey())
        msg = receive( n, 32768, server_session_key)
        
        msg = msg.split(b"::")

        other_pub = msg[2]
        signat = json.loads(msg[1])
        cipher = PKCS1_OAEP.new(RSAkey)
        message = cipher.decrypt(msg[0])

        digest = MD5.new(message).digest()

        if not RSA.importKey(other_pub).verify(digest, signat):
            sys.exit("Signer verification failed")
        eightByte = message

        key_128 = eightByte + eightByte[::-1]
        AESKey = AES.new(key_128, AES.MODE_CBC,IV=key_128)
        toOtherMsg = AESKey.encrypt(Padding("OK"))
        send(n, toOtherMsg, server_session_key)

        done = receive( n, 512, server_session_key)
        send(n, "got".encode(), server_session_key)
        if done.decode() == "DONE":
            other_pseud = receive(n, 2048, server_session_key).decode()
            send(n, "pseud ok".encode(), server_session_key)
            players_sess_keys.append([other_pseud,key_128])

    elif msg == "999":
        
        break


######################################################################
# Send msg to other player
######################################################################

def sendToPlayer(destPlayer, dic, listName):

    dic['player'] = destPlayer
    dic['code'] = 10

    key_128 = ""
    for ar in players_sess_keys: #buscar chave de sessão para o jogador destino
        if ar[0] == destPlayer:
            key_128 = ar[1]

    AESKey = AES.new(key_128, AES.MODE_CBC,IV=key_128)
    toOtherMsg = AESKey.encrypt(Padding(str(dic[listName])))
    dic[listName] = base64.b64encode(toOtherMsg).decode()

    digest = hmac.new(key_128, dic[listName].encode(), hashlib.sha1).hexdigest()
    toSend = dic[listName] + "_:_" + digest

    dic[listName] =  toSend

    send(n, str.encode(json.dumps(dic)) , server_session_key)


######################################################################
# Receive msg from other player
######################################################################

def rcvFromPlayer(dic, listName):
    key_128 = ""
    for ar in players_sess_keys: #buscar chave de sessão para o jogador source
        if ar[0] == dic['player']:
            key_128 = ar[1]

    ar = dic[listName].split("_:_")
    
    digest = hmac.new(key_128, ar[0].encode(), hashlib.sha1).hexdigest()
    if digest != ar[1]:
        sys.exit("Message authentication failed.")
    dic[listName] = ar[0]

    AESKey = AES.new(key_128, AES.MODE_CBC,IV=key_128)
    stringPublicKeys = RemovePadding(AESKey.decrypt(base64.b64decode(dic[listName])).decode('ascii'))

    dic[listName] = stringPublicKeys.replace("'","").replace("[","").replace("]","").split(", ")

    return dic

######################################################################
# Random Key
######################################################################
def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

######################################################################
# Is the tile in my hand ?
######################################################################
def is_tile_in_my_hand(tile):
    var = False
    for t in hand:
        if (t[0]==tile[0] and t[1]==tile[1]) or (t[0]==tile[1] and t[1]==tile[0]):
            var = True
    return var

def id_tile_in_list(tile, list):
    var = False
    for t in list:
        if (t[0]==tile[0] and t[1]==tile[1]) or (t[0]==tile[1] and t[1]==tile[0]):
            var = True
    return var
    
######################################################################
# AI Play
######################################################################

def AIPlay(dic):
    table = dic['chain']
    if not table: #Se mesa vazia, joga a peça 0
        return '0'
    for t in range(len(hand)):
        for p in hand[t]:
            if table[0][0] == p or table[-1][1] == p:
                
                return str(t)
    
    return 's'

#############################################
# Main Cycle
#############################################
while True:
    
    msg = receive(n,16384,server_session_key).decode()
    
    if msg:
        dic = json.loads(msg)

        #############################################
        # Stock Encryption and Save Keys
        #############################################
        if dic['code'] == 101:
            newStock = []
            for t in dic['dominoSet']:
                done = False
                while not done:
                    # Key generation
                    key = get_random_string(16)

                    # Cipher init
                    iv = os.urandom(algorithms.AES.block_size//8);

                    cipher_aes = AES.new(key, AES.MODE_CFB, iv)

                    # Encryption
                    plaintext = str(t) 
                    ciphertext = cipher_aes.encrypt(plaintext)
                    
                    if ciphertext not in keysUsed:
                        done = True

                # Store data
                keysUsed.append((base64.b64encode(ciphertext).decode('ascii'), key, base64.b64encode(iv).decode('ascii')))
                newStock.append(base64.b64encode(ciphertext).decode('ascii'))


            # Shuffle the deck
            for index in range(0, 27):
                tradeIdx = random.randint(0, 27)
                aux = newStock[tradeIdx]
                newStock[tradeIdx] = newStock[index]
                newStock[index] = aux

            dic = {'dominoSet': newStock}
            
            send(n,str.encode(json.dumps(dic)),server_session_key )
        #############################################
        # Tile Selection
        #############################################
        elif dic['code'] == 102:

            if dic['player'] != None:
                dic = rcvFromPlayer(dic, 'chosenDominos')
            
            if choices < 5:
                takeOrPass = random.randint(1, 100)
                if (takeOrPass <= 5 and takeOrPass >= 1):
                    tile = random.randint(0, 27)
                    if dic['chosenDominos'][tile] == 'False':
                        dic['chosenDominos'][tile] = 'True'
                        choices += 1
                        initialHand.append(dic['dominoSet'][tile])
                        print("Chose Tile ", tile)

                #############################################
                # Bit commitment
                #############################################
                if ready != 1 and choices == 5:
                    ready = 1
                    R1 = base64.b64encode(bytes(random.randint(1000, 5000))).decode('ascii')
                    R2 = base64.b64encode(bytes(random.randint(1000, 5000))).decode('ascii')
                    bitCommit = hash(''+R1+R2+str(initialHand))
                    dic['commit'] = True
                    dic['bitCommitment'] = [bitCommit, R1]
                    print("\n[!] Initial Hand: ", initialHand)

            cont = 0
            for c in dic['chosenDominos']:
                if c == 'True':
                    cont+= 1

            player = mypseudonym

            if cont == len(players_list) * 5:
                dic['nPlayersReady'] = True
                send(n, str.encode(json.dumps(dic)) , server_session_key)
            else:
                while player == mypseudonym:
                    x = random.randint(0, len(players_list)-1)
                    player = players_list[x]
                 
                sendToPlayer(player, dic, 'chosenDominos')

        #############################################
        # Other player Bit commits save
        #############################################
        elif dic['code'] == 103:
            bitCommits = dic['bitCommits']
            decryptedHand = initialHand
            send(n, json.dumps({'OK': 'Done'}).encode("ascii") , server_session_key )
        #############################################
        # Revelation Stage (keys and IV's)
        #############################################
        elif dic['code'] == 104:
            index = 0
            keyI = 0
            keys = dic['keys']
            ciphers = []
            for k in keysUsed:
                ciphers += [k[0]]

            for t in dic['chosenDominos']:
                if t == 'True':
                    tIndex = ciphers.index(dic['dominoSet'][index])
                  
                    keys[keyI].append((keysUsed[tIndex][1], keysUsed[tIndex][2]))
                    keyI += 1
                index+=1

            dic['keys'] = keys
         
            send(n, json.dumps(dic).encode("ascii"), server_session_key)
        #############################################
        # Hand Decryption
        #############################################
        elif dic['code'] == 105:
            dominoSet = []

            for it in range(len(dic['keys'][0])):
                index = 0
                keyIndex = 0
                for t in dic['dominoSet']:
                    if dic['chosenDominos'][index] == 'True':
                        # Decryption
                        for hi in range(len(decryptedHand)):
                            if t in decryptedHand[hi]:
                                cipher_aes = AES.new(dic['keys'][keyIndex][it][0], AES.MODE_CFB, base64.b64decode(dic['keys'][keyIndex][it][1]))
                        
                                #print("TRIO: ", t, dic['keys'][keyIndex][it][0], dic['keys'][keyIndex][it][1])
                                ciphertext = base64.b64decode(t) 
                                plaintext = cipher_aes.decrypt(ciphertext)
                                #print("T of TRIO", plaintext.decode('ascii'))
                                decryptedHand[hi] = plaintext.decode('ascii')
                                dic['dominoSet'][index] = plaintext.decode('ascii')

                        keyIndex+=1
                    
                    index+=1

            #print('\n[!] Decrypted Hand: ', decryptedHand)


            for t in decryptedHand:
                if '[' in t:
                    ar = t.replace('[', '').replace(']', '').split(', ')
                    myTilesIndexes.append(int(ar[0]))
                    myTilesPseud.append(ar[1])
            
            send(n, json.dumps(dic).encode("ascii"), server_session_key)
        #####################################################################
        # 6. Tile de-anonymization preparation stage
        #####################################################################
        elif dic['code'] == 66 or dic['code'] == 10: #Jogador recebe o array de chaves públicas e adiciona as suas

            #Gera os 5 pares de chaves, no caso de não o ter feito
            if not myTilesKeys:
                for i in range(len(myTilesIndexes)):
                    myTilesKeys.append(generateAK2())
            
            if dic['code'] == 10:
                dic = rcvFromPlayer(dic, 'publicKeys')
            if keyCount < 5:
                takeOrPass = random.randint(1, 100)
                if (takeOrPass <= 5 and takeOrPass >= 1):
                    if dic['publicKeys'][myTilesIndexes[keyCount]] == 'None':
                        private_key = myTilesKeys[keyCount][1]
                        public_key = myTilesKeys[keyCount][0]
                        pem = public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        dic['publicKeys'][myTilesIndexes[keyCount]] = base64.b64encode(pem).decode('ascii') 

                        keyCount += 1

            cont = 0
            for c in dic['publicKeys']:
                if c != 'None':
                    cont+= 1

            player = mypseudonym

            if cont == len(players_list) * 5:
                dic['nPlayersReady'] = True

                send(n, str.encode(json.dumps(dic)) , server_session_key)
            else:
                while player == mypseudonym:
                    x = random.randint(0, len(players_list)-1)
                    player = players_list[x]

                sendToPlayer(player, dic, 'publicKeys')
        #####################################################################
        # 7. Tile de-anonymization stage
        #####################################################################

        elif dic['code'] == 67:
            hand = []
            cont = 0
            for i in myTilesIndexes:
                encryptedTile = base64.b64decode(dic['dominoSet'][i])
                decryptedTile = myTilesKeys[cont][1].decrypt(
                    encryptedTile,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                tile = (decryptedTile[0], decryptedTile[1])

                hand.append(tile)

                cont+=1
            print("\n[!] Hand : ",hand)
            send(n, str.encode(json.dumps(dic)) , server_session_key)
        #############################################
        # Game
        #############################################
        elif dic['code'] == 1000:
            print("Game over! Cheating acusation! ")
            send(n, str.encode(json.dumps(dic)) , server_session_key)
            sys.exit()

        elif dic['code'] == 205: # CHECK BIT COMMITS
            print("\n[!] Checking bit commitment")
            if dic['BCdata'] != []:
                bitCommitPlayer = hash(''+dic['BCdata'][0]+dic['BCdata'][1]+str(dic['BCdata'][2]))
                if bitCommitPlayer not in bitCommits or dic['BCdata'][0] not in bitCommits or (bitCommits.index(bitCommitPlayer)!=bitCommits.index(dic['BCdata'][0])):
                    dic['BCcheck'] = False
            else:
                dic['BCdata'] = (R1, R2, initialHand)
            send(n, str.encode(json.dumps(dic)), server_session_key)

        elif dic['code'] == 3: # Informa da jogada de outro jogador e pergunta se concorda

            s = id_tile_in_list(dic['tile'], hand) or id_tile_in_list(dic['tile'], dic['chain'])
            if s:
                dic['code'] = 5
            else:
                dic['code'] = 4

            send(n, str.encode(json.dumps(dic)) , server_session_key)

        elif dic['code'] == 201: #Jogador x ganhou
            print('\n[!] Player '+str(dic['player'])+' has won')
      
            send(n, str.encode(json.dumps(dic)) , server_session_key)
            break

        elif dic['code'] == 202: #Jogador x ganhou
            print('\n[!] Server: You won!')
  
            win_points = 10

            send(n, str.encode(json.dumps(dic)) , server_session_key)

            # Receive a json message from the game
            print("\n    [!] Receiving the game info message!")
            game_info = receive(n, 2048, server_session_key).decode()
            if game_info != 'not_cc':
                game = json.loads(game_info)
                print("        [!] Got the message!")
               
                #Check if I earned correctly the points
                for p in game['Game']:
                    if p['Player'] == mypseudonym:

                        if check_points_match(p['Points'], win_points, mypseudonym, game):
                            print("            [!] ACCEPTED: Points match\n")
                     
                        else:
                            print("            [!] NOT ACCEPTED: Points not matched!\n")
                        
                break
            else:
                print("        [!] No CC match, points not attributed!")
                break
        elif dic['code'] == 203: # Empate    
            print('\n[!] Server: Tie.')
      
            send(n, str.encode(json.dumps(dic)) , server_session_key)
            break

        #####################################################
        # STOCK ACCESS PROCESS
        #####################################################
        elif dic['code'] == 106:
            if not dic['stock']:
                dic['code'] = 2
                
            else:
                tile = random.randint(0, len(dic['stock'])-1)
                print("\n[!] Chose tile: "+ str(tile) + " from stock ")
                tileStock = dic['stock'].pop(tile)
                
                dic['tileS'] = tileStock
            
            send(n, str.encode(json.dumps(dic)) , server_session_key)
        elif dic['code'] == 107:
            tile = dic['tileS']
            
            if dic['keys'] == []:
                tIndex = ciphers.index(tile)
                dic['keys'].append((keysUsed[tIndex][1], keysUsed[tIndex][2]))
               
            else:
                if tileStock != None:
                    cipher_aes = AES.new(dic['keys'][0][0], AES.MODE_CFB, base64.b64decode(dic['keys'][0][1]))
                        
                    #print("TRIO: ", tile, dic['keys'][0][0], dic['keys'][0][1])
                    ciphertext = base64.b64decode(tile) 
                    plaintext = cipher_aes.decrypt(ciphertext)
                    #print("T of TRIO", plaintext.decode('ascii'))
                    tileStock = plaintext.decode('ascii')
                    dic['tileS'] = plaintext.decode('ascii')

            send(n, str.encode(json.dumps(dic)) , server_session_key)

        elif dic['code'] == 108:
            
            if tileStock != None:
                pubKStock, privKStock = generateAK2()
                pem = pubKStock.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                dic['StockKey'] = base64.b64encode(pem).decode('ascii')

            
            send(n, str.encode(json.dumps(dic)) , server_session_key)

        elif dic['code'] == 109:
            if tileStock != None:
                encryptedTile = base64.b64decode(dic['tileS'])
                decryptedTile = privKStock.decrypt(
                    encryptedTile,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                tile = (decryptedTile[0], decryptedTile[1])
                print("\n [!] Tile from stock is: ",tile)
                hand.append(tile)
            tileStock = None
            pubKStock = None
            privKStock = None
           
            send(n, str.encode(json.dumps(dic)) , server_session_key)  
        #####################################################

        elif dic['playersReady']:
            chain = dic['chain']
            
            print('Chain:', chain)

            print('\n'.join([str(hand.index(d))+': '+str(d) for d in hand]))

            if isAI:
                choice = AIPlay(dic)
            else:
                choice = input("Which do you want to play? Enter p to pass, c to cheat and s to stock.")

            if choice == 'p': #Pass
                dic['code'] = 2
                print("Pass.")

            elif choice == 's': #Stock
                dic['code'] = 6
                print("\n[!] Asking server for the stock. \n")

            else:
                if choice == 'c': #Inventar tile
                    x = input("Insert the first number: ") 
                    y = input("Insert the second number: ")
                    tpl = (int(x), int(y))

                elif choice.isdigit():
                    if (int(choice) < 0 or int(choice) >= len(hand)):
                        print("Invalid domino number!")
                    else:
                        tpl = hand[int(choice)]
                    
                dic['tile'] = tpl
                print("\n [!] Tile played: ",dic['tile'])
                if len(hand) == 1: #Verifica se já não tem mais peças para além da que jogou para poder dizer que ganhou
                    dic['code'] = 200
               
                send(n, str.encode(json.dumps(dic)) , server_session_key)

               
                dic = receive(n, 16384, server_session_key).decode()
                
                dic = json.loads(dic)
                if dic['code'] == 0 and choice.isdigit():
                    print("\n [!] Server: Valid tile.")
                    hand.pop(int(choice))
                elif dic['code'] == 1:
                    print("\n[!] Server: Invalid tile! Play again.")
                elif dic['code'] == 1000:
                    print("Game over! Cheating acusation! ")
                    send(n, str.encode(json.dumps(dic)) , server_session_key)
                    sys.exit()
                dic['code'] = 0
           
            send(n, str.encode(json.dumps(dic)) , server_session_key) 
                
        else:
            send(n, str.encode(json.dumps(dic)) , server_session_key)

print("\n[!] Game Over")  

