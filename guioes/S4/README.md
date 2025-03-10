# Guião 2


## Questões 1
`Qual o impacto de se considerar um NONCE fixo (e.g. tudo 0)? Que implicações terá essa prática na segurança da cifra?`

Ao utilizar um nonce fixo (por exemplo, tudo 0), compromete-se seriamente a segurança da cifra. O nonce é uma parte importante da criptografia porque garante que cada mensagem tenha um fluxo de chave único, mesmo que a mesma chave seja utilizada em diferentes mensagens.

Se o nonce for fixo, o fluxo de chave gerado será sempre o mesmo, o que significa que, ao cifrar várias mensagens com a mesma chave e nonce, o fluxo de chave será repetido. Isso torna a cifra vulnerável, pois, se um atacante obtiver dois criptogramas cifrados com o mesmo nonce e chave, ele pode realizar um XOR entre os dois para eliminar o fluxo de chave, revelando informações sobre os dados originais.

Usar um nonce fixo compromete a confidencialidade, pois permite que o atacante descubra o fluxo de chave e, eventualmente, decifre os dados. Portanto, é crucial que o nonce seja sempre único para cada cifragem, garantindo segurança.


## Questões 3
`Qual o impacto de utilizar o programa chacha20_int_attck.py nos criptogramas produzidos pelos programas cfich_aes_cbc.py e cfich_aes_ctr.py? Comente/justifique a resposta. `

O algoritmo do programa chacha20_int_attck.py realiza um ataque por meio de uma manipulação específica do texto cifrado, onde uma parte do texto cifrado é alterada com base em uma palavra conhecida e substituída por um novo texto, sem precisar da chave.

O programa cfich_aes_cbc.py utiliza uma cifra por bloco, e não por fluxo. Isso significa que cada bloco de texto depende do bloco anterior, o que faz com que, ao alterarmos o texto como o programa malicioso propõe, todos os blocos seguintes sejam afetados, tornando o ataque do programa ineficaz neste contexto. A corrupção de um bloco prejudicaria a decodificação correta do texto original.

O programa cfich_aes_ctr.py utiliza uma cifra de fluxo, empregando o modo contador (CTR), que combina o texto com uma operação XOR. Como o ataque consiste na alteração de uma certa parte do texto cifrado, neste algoritmo o ataque seria bem-sucedido, sem afetar a integridade global da cifra. Portanto, o impacto do programa malicioso seria significativo.