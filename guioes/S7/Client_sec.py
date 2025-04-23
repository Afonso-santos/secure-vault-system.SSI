# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sec_pbenc import KeyDerivation

conn_port = 7777
max_msg_size = 9999

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.password = b'password'  # Shared password

    def process(self, msg=None):
        """ Encripta mensagem antes de enviar e desencripta mensagem recebida. """
        if msg:  # If receiving a message
            print(f"Recebido ({self.msg_cnt}): Mensagem encriptada")
            if len(msg) < 64:
                print("Erro: Mensagem recebida é muito curta!")
                return None

            signature, salt, iv, ciphertext = msg[:32], msg[32:48], msg[48:64], msg[64:]

            key = KeyDerivation(self.password, salt)
            aes_key, hmac_key = key[:32], key[32:]

            # Verify HMAC
            try:
                hmac_obj = hmac.HMAC(hmac_key, hashes.SHA256())
                hmac_obj.update(ciphertext)
                hmac_obj.verify(signature)
                print("Assinatura válida.")
            except:
                print("Erro: Assinatura inválida!")
                return None

            # Decrypt message
            try:
                algorithm = AESGCM(aes_key)
                plaintext = algorithm.decrypt(iv, ciphertext, None)
                print(f"Recebido ({self.msg_cnt}): {plaintext.decode()}")
            except:
                print("Erro ao descriptografar a mensagem.")
                return None

        # Prompt user for input
        new_msg = input("Digite sua resposta (vazio para sair): ").encode()
        if not new_msg:
            return None  # Exit if user sends an empty message

        # Encrypt message
        salt = os.urandom(16)
        key = KeyDerivation(self.password, salt)
        aes_key, hmac_key = key[:32], key[32:]

        iv = os.urandom(16)
        algorithm = AESGCM(aes_key)
        ciphertext = algorithm.encrypt(iv, new_msg, None)

        # Generate HMAC signature
        hmac_obj = hmac.HMAC(hmac_key, hashes.SHA256())
        hmac_obj.update(ciphertext)
        signature = hmac_obj.finalize()

        return signature + salt + iv + ciphertext
    
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