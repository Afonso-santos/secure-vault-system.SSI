# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

conn_port = 7777
max_msg_size = 9999

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0 # Contador para gerir os passos do handshake e comunicação

        # Fixed Diffie-Hellman parameters
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2
        parameters = dh.DHParameterNumbers(p, g).parameters()
        self.client_priv_key = parameters.generate_private_key()
        self.client_pub_key = self.client_priv_key.public_key()

        self.shared_key = None
        self.aesgcm = None
        self.server_pub_key = None 

    def process(self, msg=None):
            if self.msg_cnt == 0 and msg is None:
                self.msg_cnt += 1
                return self.client_pub_key.public_bytes(
                    Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                )

            elif self.msg_cnt == 1 and msg is not None:
                try:
                    server_pub_key = load_der_public_key(msg)
                    self.shared_key = self.client_priv_key.exchange(server_pub_key)

                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None, 
                        info=b'handshake data',
                    ).derive(self.shared_key)

                    self.aesgcm = AESGCM(derived_key)
                    self.msg_cnt += 1 

                    print("Canal seguro estabelecido!")
                    primeira_mensagem = input("Digite a primeira mensagem a enviar: ")
                    print(f"Mensagem do cliente: {primeira_mensagem}")
                    primeira_mensagem = primeira_mensagem.encode()

                    if not primeira_mensagem:
                        return None 

                    nonce = os.urandom(12) 
                    ciphertext = self.aesgcm.encrypt(nonce, primeira_mensagem, None)
                    return nonce + ciphertext 
                except ValueError:
                    return None

            elif self.msg_cnt >= 2:
                if msg:
                    try:
                        nonce = msg[:12]
                        ciphertext = msg[12:]
                        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
                        print(f"Mensagem do servidor: {plaintext.decode()}")
                    except Exception:
                        return None

                while True:
                    new_msg = input("Digite sua resposta (ou deixe vazio para sair): ").encode()
                    if not new_msg:
                        return None 

                    nonce = os.urandom(12)
                    ciphertext = self.aesgcm.encrypt(nonce, new_msg, None)
                    return nonce + ciphertext 

    
#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    
    while msg:
        writer.write(msg)
        await writer.drain()
        msg = await reader.read(max_msg_size)
        if msg:
            msg = client.process(msg)
        else:
            break
    
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()
    await writer.wait_closed()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())

run_client()