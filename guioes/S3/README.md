# Guião 1

## Questão 1

Qual a versão da biblioteca cryptography instalada?
```txt
A versão instalada da biblioteca do cryptography é  44.0.1
```
## Questões 2
Consegue observar diferenças no comportamento dos programas otp.py e bad_otp.py ? Se sim, quais?
```txt
A principal diferença entre os dois programas está na geração da chave. No **otp.py**, a chave é criada usando `os.urandom(nbytes)`, que gera números verdadeiramente aleatórios com base na entropia do sistema operacional. Esse método coleta ruído aleatório de diversas fontes de hardware, como eventos de rede, variações de temperatura da CPU e movimentação do mouse, garantindo um nível elevado de segurança e imprevisibilidade.  

Já no **bad_otp.py**, a chave é gerada com `random.seed(random.randbytes(2))` e `random.randbytes(n)`, o que significa que depende de um gerador de números pseudoaleatórios (PRNG) **não seguro para criptografia**. Como o PRNG gera sequências previsíveis sempre que a mesma seed é definida, a chave pode ser facilmente reproduzida, comprometendo a segurança do sistema.
```

## Questões 3
```txt

O ataque realizado ao **bad_otp.py** não contradiz a segurança absoluta do **One-Time Pad (OTP)**, pois o problema não está no próprio algoritmo OTP, mas sim na implementação incorreta da geração da chave.  

A segurança absoluta do OTP é garantida apenas quando a chave é **verdadeiramente aleatória, tão longa quanto a mensagem, usada apenas uma vez e mantida secreta**. No entanto, no **bad_otp.py**, a chave é gerada a partir de um **PRNG inseguro** com uma seed previsível, o que significa que pode ser **reproduzida**. Como o espaço de chaves possíveis é pequeno (devido à limitação de 16 bits na seed), um atacante pode testar todas as possíveis chaves geradas e descobrir a mensagem original. Isso demonstra que a vulnerabilidade está na implementação e **não na teoria do One-Time Pad**.

```
