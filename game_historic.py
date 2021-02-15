import os
import json
import scandir #É necessário instalar -> sudo pip3 install scandir
from PyKCS11 import *
from cryptography.hazmat.primitives.serialization import load_der_public_key,Encoding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import json

signature_match = True
global game_info_arr

try:
    lib = '/usr/local/lib/libpteidpkcs11.so'

    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib)
    slots = pkcs11.getSlotList()
    classes = {
    CKO_PRIVATE_KEY : ' private key ',
    CKO_PUBLIC_KEY : ' public key ',
    CKO_CERTIFICATE : ' certificate '
    }

    for slot in slots :
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
            session = pkcs11.openSession(slot)
            objects = session.findObjects()

            
            print("________________________")

            try:
                info = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), 
                    (PyKCS11.CKA_LABEL,  "CITIZEN AUTHENTICATION CERTIFICATE")])
                der = bytes([c.to_dict()['CKA_VALUE'] for c in info][0])
              
                cert = x509.load_der_x509_certificate(der, default_backend()).public_bytes(Encoding.PEM)

                cert2 = x509.load_pem_x509_certificate(cert, default_backend())

                publicKey = cert2.public_key()
                
         
            except Exception as e:
                print(e)
 
        else:
            print("[!] No card found")
except Exception as E:
    print(E)
    print("[!] No card found!")




#ATENCAO: Os ficheiros na pasta "accounting" têm que conter a informação em binário.
#------------------------------------------------------------------------------#
def search_files():
    global game_info_arr

    # File path
    path = os.getcwd()+'/accounting/'
    game_info_arr = []

    # Iterate over the founded files
    with os.scandir(path) as it:
        for entry in it:
            # Check if files are txt type
            if entry.name.endswith(".txt") and entry.is_file():
                file = str(entry).split('/')
                new_file = str(file).split("'")
                file_name = str(new_file[1])

                # Read files and separate signature and game info
                try:
                    with open(path+file_name, "rb") as f:
                        data = f.read()
                        f.close()

                    data_out = data.split(b":_:")
                    game_info = data_out[0]
                    signature = data_out[1]
                    
                 
                    signature_match = publicKey.verify( signature , game_info , padding.PKCS1v15(), hashes.SHA1() )
                    # Check if signature is valid
                
                    if signature_match is None:
                        # Save all games into the games array
                        print("[!] Signature match!")
                        game_info_arr.append(game_info)
                    else:
                        print("[!] Signature not match!")
                except Exception as exception:
                    print(exception)

    return game_info_arr

#-----------------------------------------------------------------------------#
games_arr = search_files()

if not games_arr:
    print("[!] No games record found!")
else:
    # Print all games
    for item in games_arr:
        print(item)
# ------------------------------------------------------------------------------ #

            
