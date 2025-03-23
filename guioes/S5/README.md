# Guião 03

## Questão 1

`Qual o impacto de executar o programa chacha20_int_attck.py sobre um criptograma produzido por pbenc_chacha20_poly1305.py? Justifique.`

O programa `chacha20_int_attck.py` explora a vulnerabilidade presente na cifra ChaCha20 standard, que consiste na ausência de mecanismos de integridade. Ou seja, é possível modificar o criptograma sem que essas alterações sejam detetadas.

Por outro lado, o programa `pbenc_chacha20_poly1305.py` utiliza uma versão do ChaCha20 que respeita os três pilares da segurança: confidencialidade, integridade e autenticidade.

Assim, ao aplicar o programa malicioso sobre um criptograma gerado por esta versão reforçada do ChaCha20, a integridade é, de facto, corrompida, mas essa alteração é imediatamente detetada. Qualquer modificação resulta num erro na fase de descodificação, sendo a alteração bloqueada e a mensagem rejeitada.

## Questão 2
`Qual o motivo da sugestão de usar m2 com mais de 16 byte? Será possível contornar essa limitação?` 

A sugestão de utilizar uma mensagem `m2` com mais 16 bytes prende-se ao facto de o CBC-MAC funciona com blocos de 16 bytes. Consequentemente facilita ao ataque porque cria dependências entre bloco. 
