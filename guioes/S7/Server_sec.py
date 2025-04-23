# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sec_pbenc import KeyDerivation

conn_cnt = 0
conn_port = 7777
max_msg_size = 9999

class ServerWorker:
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.password = b'password'  # Shared secret

    def process(self, msg):
        """ Processa uma mensagem do cliente e responde com uma mensagem criptografada. """
        self.msg_cnt += 1

        if len(msg) < 64:
            print("Erro: Mensagem recebida muito curta!")
            return None

        signature, salt, iv, ciphertext = msg[:32], msg[32:48], msg[48:64], msg[64:]

        print(f"Recebido ({self.id}): Mensagem encriptada")
        print(f"Signature: {signature.hex()}")
        print(f"Salt: {salt.hex()}")
        print(f"IV: {iv.hex()}")

        # Derivar a chave a partir da senha e do salt
        key = KeyDerivation(self.password, salt)
        aes_key, hmac_key = key[:32], key[32:]

        # Verificar HMAC
        try:
            hmac_obj = hmac.HMAC(hmac_key, hashes.SHA256())
            hmac_obj.update(ciphertext)
            hmac_obj.verify(signature)
            print("Assinatura válida.")
        except:
            print("Erro: Assinatura inválida!")
            return None

        # Decriptar mensagem
        try:
            algorithm = AESGCM(aes_key)
            plaintext = algorithm.decrypt(iv, ciphertext, None)
            print(f"Mensagem descriptografada: {plaintext.decode()}")
        except:
            print("Erro ao descriptografar a mensagem.")
            return None

        # Gerar resposta criptografada
        response_msg = plaintext.upper()
        print(f"Resposta: {response_msg}")

        if not response_msg:
            return None

        salt = os.urandom(16)
        key = KeyDerivation(self.password, salt)
        aes_key, hmac_key = key[:32], key[32:]

        iv = os.urandom(16)
        algorithm = AESGCM(aes_key)
        ciphertext = algorithm.encrypt(iv, response_msg, None)

        # Criar assinatura HMAC
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


async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    data = await reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1]==b'\n': break
        data = srvwrk.process(data)
        if not data: break
        writer.write(data)
        await writer.drain()
        data = await reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_server()