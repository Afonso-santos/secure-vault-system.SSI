#!/bin/bash

# (limpar ficheiros previamente criados)

rm lisboa.txt porto.txt braga.txt
rm -rf dir1 dir2

# Secção 1
echo -e "\e[34mSecção 1:\e[0m"

# Exercício 1

# (criar ficheiros)

echo -e "\e[1;32mExercício 1:\e[0m"
echo "(a criar ficheiros com conteúdo)"

echo "Lisboa" > lisboa.txt
echo "Porto" > porto.txt
echo "Braga" > braga.txt

# Exercício 2

echo -e "\e[1;32mExercício 2:\e[0m"

ls -l lisboa.txt

# Exercício 3
echo -e "\e[1;32mExercício 3:\e[0m"

chmod -v ugo+rw lisboa.txt

# Exercício 4

echo -e "\e[1;32mExercício 4:\e[0m"
chmod -v u=rx porto.txt

# Exercício 5
echo -e "\e[1;32mExercício 5:\e[0m"
chmod -v go-r braga.txt

# Exercício 6

echo -e "\e[1;32mExercício 6:\e[0m"

mkdir -v dir1
mkdir -v dir2

ls -ld dir1 dir2

# Exercício 7
echo -e "\e[1;32mExercício 7:\e[0m"

chmod -v go-x dir2

# (limpar users e grupos previamente criados)

sudo userdel -r afonso
sudo userdel -r joao
sudo userdel -r ritac

sudo groupdel grupo-ssi
sudo groupdel par-ssi

# Secção 2

echo -e "\e[34mSecção 2:\e[0m"

# Exercício 0

#echo "Exercício 0:"
# cat /etc/passwd
# cat /etc/group

# Exercício 1

echo -e "\e[1;32mExercício 1:\e[0m"
echo "(a criar utilizadores)"

sudo useradd -m -s /bin/bash afonso
sudo useradd -m -s /bin/bash joao
sudo useradd -m -s /bin/bash ritac

# Exercício 2

echo -e "\e[1;32mExercício 2:\e[0m"
echo "(a criar grupo todo)"

sudo groupadd grupo-ssi

getent group grupo-ssi 

echo "(a adicionar utilizadores ao grupo)"

sudo usermod -aG grupo-ssi afonso
sudo usermod -aG grupo-ssi joao
sudo usermod -aG grupo-ssi ritac

getent group grupo-ssi

echo "(a criar grupo pares)"

sudo groupadd par-ssi

getent group par-ssi

echo "(a adicionar utilizadores ao grupo)"

sudo usermod -aG par-ssi afonso
sudo usermod -aG par-ssi joao

getent group par-ssi

# Exercício 3

# Sim

# Exercício 4

echo -e "\e[1;32mExercício 4:\e[0m"
echo "(a mudar o dono do ficheiro braga.txt para afonso)"

sudo chown afonso braga.txt

# Exercício 5

echo -e "\e[1;32mExercício 5:\e[0m"

cat braga.txt

# Exercício 6
echo -e "\e[1;32mExercício 6:\e[0m"

# sudo su afonso


# Exercício 7
echo -e "\e[1;32mExercício 7:\e[0m"
echo "(a verificar os ids do utilizador afonso)"
id
echo "(a verificar os grupos do utilizador afonso)"
groups

# Ao rodar o comando id, obtemos o seguinte resultado:
# uid=1001(afonso) gid=1002(afonso) groups=1002(afonso),1005(grupo-ssi),1006(par-ssi)
# É indicado o id do utilizador afonso e os ids dos grupos a que pertence.

# Ao rodar o comando groups, obtemos o seguinte resultado:
# afonso grupo-ssi par-ssi
# Ou seja, o utilizador afonso pertence aos grupos afonso, grupo-ssi e par-ssi.

# Exercício 8
echo -e "\e[1;32mExercício 8:\e[0m"
echo "(a entrar como afonso e tentar ler braga.txt)"

sudo -u afonso cat braga.txt

# Exercício 9
echo -e "\e[1;32mExercício 9:\e[0m"
sudo -u afonso -s cd dir2

# O comando não executa com sucesso, pois, ao tentar aceder ao diretório dir2, o utilizador afonso não tem permissões de execução.

# (limpar users, grupos e ficheiros previamente criados)

sudo userdel -r userssi
rm reader

# Secção 3

echo -e "\e[34mSecção 3:\e[0m"


# Exercício 1
echo -e "\e[1;32mExercício 1:\e[0m"
echo "(a compilar o programa reader.c)"
gcc -o reader reader.c

# Exercício 2

echo -e "\e[1;32mExercício 2:\e[0m"

echo "(a criar utilizador userssi)"

sudo useradd -m -s /bin/bash userssi

# Exercício 3

echo -e "\e[1;32mExercício 3:\e[0m"


####### PErguntar
sudo chown -v userssi ./reader braga.txt

# Exercício 4

echo -e "\e[1;32mExercício 4:\e[0m"

./reader braga.txt

# Exercício 5
echo -e "\e[1;32mExercício 5:\e[0m"

sudo chmod -v u+s reader

# Exercício 6
#
#
#
#

echo -e "\e[1;32mExercício 6:\e[0m"



./reader braga.txt

# Comentário: 
# Ao executar novamente o programa reader, com a permissão setuid configurada, 
# o programa agora deve ser executado com os privilégios de 'userssi' (o dono do ficheiro e do programa).
# Isso significa que, mesmo que o utilizador que execute o programa seja diferente de 'userssi', 
# ele terá as permissões do utilizador 'userssi', incluindo as permissões necessárias para ler o ficheiro braga.txt.


# Secção 4

echo -e "\e[34mSecção 4:\e[0m"

# Exercício 1

echo -e "\e[1;32mExercício 1:\e[0m"

getfacl porto.txt

# Exercício 2

echo -e "\e[1;32mExercício 2:\e[0m"
echo "(a adicionar permissões de escrita ao grupo grupo-ssi)"
setfacl -m g:grupo-ssi:w porto.txt

# Exercício 3

echo -e "\e[1;32mExercício 3:\e[0m"

getfacl porto.txt

# Foram adicionadas as linhas:
# group:grupo-ssi:-w-
# mask::rw-
# Que indicam que o grupo grupo-ssi tem permissões de escrita no ficheiro porto.txt.

# Exercício 4

echo -e "\e[1;32mExercício 4:\e[0m"
echo "(a escrever no ficheiro porto.txt)"

sudo su joao -c "echo 'Portoooooo!' > porto.txt"

echo "(a ler o ficheiro porto.txt)"

sudo su joao -c "cat porto.txt"
