##################################################################################
#                                                                                #
#                  Trabalho Prático de Segurança Informática                     #
#   Tema: MON-AMOUR: Um Sistema para Trocar Cartas de Amor, mas com um Senão...  #
#                                                                                #
##################################################################################

# Sub-Biblioteca para escrever a mensagem que pretendemos enviar.
from sys import stdin

# Biblioteca para criar o Hash dos Utilizadores e Verificação de Hash de Mensagens.
import hashlib

# Biblioteca para obter o número aleatório para cifrar a mensagem.
import random

# Biblioteca para obter o tempo de resposta ao obter o hash da mensagem.
import time

# Biblioteca para verificar ficheiros nas determinadas pastas, tal como criar pastas em questão.
import os

# Sub-Biblioteca para obter o output das execuções dos comandos openssl
import subprocess

# Biblioteca para escrever a password sem aparecer os icons no input
import getpass


import uuid

# Informações dos clientes que se encontram registados.
clientsRegisted = []

clientLoggedIn = ""

#####################################################################################
#   Função para escrever a mensagem num determinado ficheiro.                       #
#   Argumentos:                                                                     #
#       - fileName: Nome do ficheiro (ou diretoria para este) que vai ser escrito.  #
#       - message: Mensagem que vai ser escrita,                                    #
#       - append: Caso seja para escrever como "appending",                         #
#                   ou para substituir pelo que está escrito                        #
#####################################################################################
def writeToFile(fileName, message, append = False):
    if append == False:
        f = open(fileName, "w")
    else:
        f = open(fileName, "a")
    f.write(message)
    f.close()

########################################################################################
#   Função para verificar se um ficheiro existe.                                       #
#   Argumentos:                                                                        #
#       - fileName: Nome do ficheiro (ou diretoria para este) que vai ser verificado.  #
########################################################################################
def fileExists(fileName):
    if os.path.exists(fileName):
        return True
    else:
        return False

########################################################################################
#   Função para ler todos os conteúdos dum ficheiro.                                   #
#   Argumentos:                                                                        #
#       - fileName: Nome do ficheiro (ou diretoria para este) que vai ser verificado.  #
########################################################################################
def readFile(fileName):
    if fileExists(fileName) == True:
        f = open(fileName, "r")

        print(f.read())

        f.close()

    input("Pressiona qualquer tecla para sair...")

########################################################################################
#   Função para apagar um determinado ficheiro.                                        #
#   Argumentos:                                                                        #
#       - fileName: Nome do ficheiro (ou diretoria para este) que vai ser apagado.     #
########################################################################################
def deleteFile(fileName):
    # Caso o ficheiro exista, vamos removê-lo do local onde se encontra
    if fileExists(fileName):
        os.remove(fileName)
        return True
    else:
        return False

########################################################################################
#   Função para obter o hash de uma determinada string.                                #
#   Argumentos:                                                                        #
#       - stringToHash: String que vai ser utilizada para obter o hash                 #
#       - filePath: Nome do ficheiro (ou diretoria para este)                          #
#                       que vai ser usado para output.                                 #
#       - withSalt: Caso seja "True", vai retornar o valor de hash,                    #
#                       juntamente com um valor de "salt" gerado aleatoriamente.       #
########################################################################################
def getHashValue(stringToHash, withSalt = False):

    if withSalt == False:
        return hashlib.sha256(stringToHash.encode('utf-8')).hexdigest()

    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + stringToHash.encode()).hexdigest() + ':' + salt


########################################################################################
#   Função para verificar se o hash (com salt) corresponde ao gerado da password.      #
#   Argumentos:                                                                        #
#       - hashedText:   Hash + Salt gerados que vai ser confirmado                     #
#       - providedText: Password que vai ser verificada                                #
########################################################################################
def matchHashedText(hashedText, password):

    # Vamos dividir a "string" fornecida, para obter os respetivos valores
    #   de hash e salt, separados com um ":" 
    _hashedText, salt = hashedText.split(':')

    # Vamos retornar um "boolean", que indica se o hash e o salt correspondem
    #   à password inserida.
    return _hashedText == hashlib.sha256(salt.encode() + password.encode()).hexdigest()

########################################################################################
#   Função para listar todos os clientes registados.                                   #
#   Argumentos:                                                                        #
#       - person: Nome do utilizador que quer receber a lista de clientes.             #
########################################################################################
def printAllTheClients(person):

    # Vai retornar todos os utilizadores registados
    print("--------------------- Utilizadores ---------------------")
    for client in clientsRegisted:
        if person not in client:
            print(client[0], end='\t')
    print("\n--------------------------------------------------------")


########################################################################################
#   Função para retornar o número de mensagens que estão por ler.                      #
#   Argumentos:                                                                        #
#       - person: Nome do utilizador da lista de mensagens.                            #
########################################################################################
def getNumberOfMessagesToRead(person):

    # Variável para contar o número de mensagens.
    line_count = 0

    # "Diretoria" do ficheiro das mensagens do utilizador
    messageFile = "messages/" + str(person) + "/message.txt"

    # Se o ficheiro existir, vamos verificar quantas linhas existem
    # As linhas com "\n" serão ignoradas, pois não são mensagens para o utilizador
    if fileExists(messageFile) == True:

        file = open(messageFile, "r")

        for line in file:
            if line != "\n":
                line_count += 1

        file.close()

    # Retorna o número de mensagens que contou (0 caso não tenha encontrado)
    return line_count


#############################################################################################
#   Função para cifrar o ficheiro, escrevendo as informações para um determinado ficheiro.  #
#   Argumentos:                                                                             #
#       - phrase: Frase que vai ser utilizada para o utilizador responder.                  #
#       - phraseAnswer: Resposta da frase mencionada acima.                                 #
#       - person: Nome do utilizador que quer enviar a mensagem.                            #
#       - personToSend: Nome do utilizador que vai receber a mensagem.                      #
#       - message: Mensagem que vai ser cifrada.                                            #
#############################################################################################
def encriptFile(phrase, phraseAnswer, person, personToSend, message):
    
    # Variável que vai contar o número de vezes que foi gerado um valor de hash 
    #   num determinado tempo (sendo como no enunciado, 15 segundos)
    
    contadorVezes = 0

    
    randomNumber = random.getrandbits(128)

    hashObtained = ""

    stringForHash = phraseAnswer + str(randomNumber)
    # Vamos guardar o tempo inicial que começou a contagem.
    start = time.time()

    # Vamos contar o tempo final que começou a contagem
    #   O valor vai alterando até a sua diferença ser igual a, no mínimo, 15 segundos.
    end = start

    while (end - start) < 15.0 :

        # Vamos juntar o valor de hash obtido ao longo do tempo, com a string que vai ser gerada outro valor de hash.
        stringForHash = stringForHash + str(hashObtained)

        # Vamos incrementar o número de vezes que gerou o Hash
        contadorVezes += 1

        # Vamos obter o valor de hash com a string requerida.
        hashObtained = getHashValue(stringForHash)

        end = time.time()


    # Vamos obter o número de mensagens existentes, em que o nome do criptograma 
    #   terá o valor da última mensagem que ainda está por ler.
    # Exemplo: Se existir um criptograma com o nome "bob-criptograma-345.aes", 
    #   será gerado a próxima mensagem com o nome "bob-criptograma-346.aes"
    numOfLines = getNumberOfMessagesToRead(personToSend)

    # Vamos escrever a mensagem que vai ser gerada num ficheiro temporário,
    #   cujo nome será o último valor de hash gerar.
    writeToFile(str(hashObtained) + ".tmp", message)

    # Vamos cifrar a mensagem que vai ser enviada, guardada no ficheiro temporário,
    #   com a chave igual ao valor de hash obtido.
    # O ficheiro resultante será guardado como um ficheiro ".aes" (devido a usar-mos o AES-128, com o modo CBC)
    cmd = 'openssl enc -aes-128-cbc -e -K'.split()


    cmd.append(hashObtained)
    cmd.append('-in')
    cmd.append(str(hashObtained) + ".tmp")
    cmd.append('-out')
    cmd.append("messages/" + str(personToSend) + "/" + str(person) + "-criptograma-" + str(numOfLines) + ".aes")
    cmd.append('-iv')
    cmd.append('0')


    # Vamos executar o comando, gerando o ficheiro cifrado.
    subprocess.run(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    
    # Vamos apagar o ficheiro temporário, visto não ser necessário neste momento.
    deleteFile(str(hashObtained) + ".tmp")

    # Vamos inserir os dados necessários da mensagem no ficheiro da pessoa que vai receber a mensagem.
    fileToGive = "messages/" + str(personToSend) + "/" + "message.txt"

    # Mensagem que vai ser inserida no ficheiro da pessoa que a vai receber.
    messageToSend = str(contadorVezes) + " | " + str(phrase) + " | " + str(randomNumber) + " | " + str(person) + "-criptograma-" + str(numOfLines) + ".aes" + "\n" 

    # Vamos escrever a mensagem no ficheiro em questão.
    writeToFile(fileToGive, messageToSend, True)

    print("A mensagem foi enviada com sucesso!")

#############################################################################################
#   Função para decifrar o ficheiro, escrevendo o texto limpo para o standard output.       #
#   Argumentos:                                                                             #
#       - fileName: O nome do ficheiro que pretendemos decifrar                             #
#       - person: Nome do utilizador que pretende ler a mensagem cifrada.                   #
#############################################################################################
def decriptFile(messageInfo, person, answer):

    # Caso o ficheiro não exista, não vale a pena tentar decifrar.
    if fileExists("messages/" + str(person) + "/" + messageInfo[3]) == False:
        print("O Ficheiro: " + str(messageInfo[3]) + "não existe!")
        return

    # Os valores necessários para a mensagem
    numOfHashesDone = int(messageInfo[0])
    numAleatorio = int(messageInfo[2])
    fileEncriptedName = messageInfo[3]

    newStringHash = answer + str(numAleatorio)
    newHashToFind = ""

    # Vamos tentar gerar o valor de hash pretendido o número de vezes igual
    #   ao valor que nos foi fornecido.
    for _ in range(0, numOfHashesDone):
        newStringHash = newStringHash + newHashToFind
        
        newHashToFind = getHashValue(newStringHash)

    # Vamos decifrar a mensagem que vai ser lida, guardada no ficheiro cifrado,
    #   com a chave igual ao valor de hash obtido.
    # O ficheiro resultante será guardado como um ficheiro ".aes" (devido a usar-mos o AES-128, com o modo CBC)
    cmd = 'openssl enc -aes-128-cbc -d -K'.split()

    cmd.append(newHashToFind)
    cmd.append('-in')
    cmd.append("messages/" + str(person) + "/"+ fileEncriptedName)
    cmd.append('-out')
    cmd.append("messages/" + str(person) + "/" + "texto-limpo.txt")
    cmd.append('-iv')
    cmd.append('0')


    # Vamos correr o comando que foi criado, para obter a mensagem. 
    subprocess.run(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    # Vamos abrir o ficheiro da mensagem que foi decifrada, em que
    #   vai ser lida a mensagem enviada 
    f = open("messages/" + str(person) + "/" + "texto-limpo.txt", "r")
    messageToRead = f.read()
    f.close()

    # Caso o texto limpo obtido tenha algum conteúdo, então a mensagem foi decifrada com sucesso!
    if len(messageToRead) > 0:

        # Vamos apagar o ficheiro cifrado, pois já não é necessário.
        deleteFile("messages/" + str(person) + "/"+ fileEncriptedName)

        # Vamos remover a mensagem do ficheiro obtido
        removeMessageFromFile("messages/" + str(person) + "/message.txt", fileEncriptedName)

        print("A Mensagem foi lida com sucesso!")
        print("Testo: " + str(messageToRead))
    else:
        print("A autenticação falhou! Não foi possível ler a mensagem!")

    # Vamos apagar o ficheiro que foi gerado ao tentar decifrar o ficheiro.
    deleteFile("messages/" + str(person) + "/" + "texto-limpo.txt")

    return

#############################################################################################
#   Função para remover uma mensagem do ficheiro da lista de mensagens                      #
#       de um utilizador.                                                                   #
#   Argumentos:                                                                             #
#       - fileName: Nome do ficheiro onde se encontra a lista de mensagens.                 #
#       - fileEncriptedName: Nome do ficheiro cifrado.                                      #
#############################################################################################
def removeMessageFromFile(fileName, fileEncriptedName):

    # Caso o ficheiro não exista, não vale a pena remover a mensagem.
    if fileExists(fileName) == False:
        return False

    # Vamos abrir o ficheiro da lista de mensagens.
    f = open(fileName, "r+")

    # Vamos ler todas as linhas das mensagens, para verificar qual o ficheiro a eliminar.
    fileLines = f.readlines()
    # Vamos colocar no início do ficheiro, para voltar a escrever desde o início.
    f.seek(0)

    # Por cada linha, vamos verificar se algum ficheiro corresponde ao criptograma.
    # Se não for, vamos escrever a linha no determinado ficheiro. 
    for line in fileLines:
        fileName = line.split(" | ")[3]

        # A razão para ter "[:-1]" é devido ao nome do ficheiro ter um "\n" no final
        if fileName[:-1] != fileEncriptedName:
            f.write(line)

    f.truncate()
    
    return True

#############################################################################################
#   Função para obter os dados para enviar a mensagem.                                      #
#   Argumentos:                                                                             #
#       - person: Nome do utilizador que pretende enviar a mensagem.                        #
#       - personToSend: Nome do utilizador que vai receber a mensagem.                      #
#############################################################################################
def sendMessage(person, personToSend):

    # Vai ser pedido ao utilizador uma pergunta e uma resposta, em que ambas vão ser utilizadas para determinar o programa.
    phrase = input("Insere aqui uma pergunta: ")
    phraseAnswer = input("Insere aqui a resposta: ")

    message = ""

    print("Escreve aqui a tua mensagem: \nNOTA: Escreve \"exit\" caso pretendas terminar a mensagem.")

    for line in stdin:
        if line != "\n" and line == "exit\n":
            if message != "\n":
                message = message[:-1]
                break

        message = message + line

    # Caso a mensagem não seja vazia, o ficheiro vai ser cifrado.
    if message:    
        encriptFile(phrase, phraseAnswer, person, personToSend, message)
    else:
        print("Lamento, mas não é permitido enviar mensagens vazias!")

#############################################################################################
#   Função para obter o nome da pessoa que vai receber a mensagem.                          #
#   Argumentos:                                                                             #
#       - person: Nome do utilizador que pretende enviar a mensagem.                        #
#############################################################################################
def selectPersonToSend(person):
    printAllTheClients(person)

    personToSend = input("Escreve a pessoa que pretendes enviar a mensagem: ")

    while person == personToSend or checkIfUserAlreadyExists(personToSend) == False:
        printAllTheClients(person)
        print("Lamento, mas esta opção é inválida!")
        personToSend = input("Escreve novamente a pessoa que pretendes enviar a mensagem: ")

    sendMessage(person, personToSend)
    


#############################################################################################
#   Função para escolher a mensagem que vai ser decifrada.                                  #
#   Argumentos:                                                                             #
#       - person: Nome do utilizador que pretende ler a mensagem.                           #
#############################################################################################
def checkMessage(person):

    # Lista das mensagens registadas na altura que o utilizador pretende ver.
    messagesRegistered = []

    #  Nome do ficheiro que pretendemos ver as mensagens que faltam ler.
    messagesStoredFile = "messages/" + str(person) + "/message.txt"

    # Caso o ficheiro não exista, significa que não existem mensagens por ler.
    if fileExists(messagesStoredFile) == False:
        print("Não existem mensagens para ler neste momento!")
    else:
        f = open(messagesStoredFile, "r")

        # Vamos ler todas as mensagens do ficheiro das mensagens por ler.
        fileLines = f.readlines()

        # Caso existam alguma mensagem para ler, o tamanho da lista será maior que 0, senão
        #   vamos indicar que não existem mensagens para ler.
        if len(fileLines) > 0:

            # Inteiro utilizador para realizar a contage
            counterLines = 0
            for line in fileLines:

                # Todas as linhas podem possuir um "\n" no final (caso seja enviada a mensagem, devido ao "appending"), portanto
                #   vamos verificar se existe um "\n" no final, e removê-lo da String do nome do criptograma.
                if(fileLines[counterLines][3][-1] == '\n'):
                    fileLines[counterLines][3] = fileLines[counterLines][3][:-1]
                
                # Cada linha possui o seguinte formato: número de iterações hash | Pergunta | Número aleatório | Criptograma
                #   Ou seja, vamos realizar um "split" na linha, transformando num array, para realizar as respetivas divisões.
                stringToSplit = line.split(" | ")

                # Todas as linhas podem possuir um "\n" no final (caso seja enviada a mensagem, devido ao "appending"), portanto
                #   vamos verificar se existe um "\n" no final, e removê-lo da String do nome do criptograma.
                if(stringToSplit[3][-1] == '\n'):
                    stringToSplit[3] = stringToSplit[3][:-1]

                # Vamos adicionar a linha dividida para uma lista onde vai conter todas as mensagens em questão.
                messagesRegistered.append(stringToSplit)
                
                # Vai indicar ao Utilizador quais são as mensagens que ainda estão por ler.
                # O Nome destas está incluido no nome do ficheiro (p.e, "bob" -> "bob-criptograma-X.aes").
                print(str(counterLines+1) + ") " + str(stringToSplit[3].split("-")[0]) + " -> " 
                    + str(stringToSplit[0]) + " | " + str(stringToSplit[1]) + " | " + str(stringToSplit[2]) + " | " + str(stringToSplit[3]))
                
                # Vai adicionar 1 devido ao utilizador ter de selecionar uma opção.
                counterLines += 1


            # Vamos obter a opção que o utilizador pretende obter a mensagem.
            # A Razão para verificar por exceptions, é devido ao utilizador não colocar um inteiro como opção e assim, não crashar o programa.
            try:
                optionMessage = int(input("Escreve o número da opção que pretendes ver a mensagem: "))
            except ValueError:
                optionMessage = -1


            # Enquanto a opção que temos não corresponder ao número de opções das mensagens, vamos pedir novamente um número.
            while optionMessage < 0 or optionMessage > len(messagesRegistered):
                print("Este ficheiro não existe na lista de mensagens!")
                try:
                    optionMessage = int(input("Escreve novamente a opção da mensagem que pretendes ver: "))
                except ValueError:
                    optionMessage = -1


            # Vai ser mostrada a pergunta e o utilizador terá de saber a resposta, de forma a que consiga ver a mensagem.
            print("Pergunta: " + messagesRegistered[optionMessage-1][1])
            answer = input("Insere aqui a tua resposta: ")

            # Vai-se tentar decifrar o ficheiro com a resposta submetida.
            decriptFile(messagesRegistered[optionMessage-1], person, answer)
        else:
            print("Não existem mensagens para ler neste momento!")


#############################################################################################
#   Menu após realizar o login.                                                             #
#   Argumentos:                                                                             #
#       - person: Nome do utilizador que pretende realizou o login.                         #
#############################################################################################
def menuAposLogin(person):
    menuOption = -1

    while True:
        print("------------------- Menu Após Login --------------------")
        print("| 1. Enviar uma mensagem;                              |")
        print("| 2. Ver uma mensagem;                                 |")
        print("| 3. Menu de Ajuda;                                    |")
        print("| 4. Sair;                                             |")
        print("--------------------------------------------------------")

        menuOption = input("Seleciona uma opção: ")

        if menuOption == "1":
            #sendMessage(person)
            selectPersonToSend(person)
        elif menuOption == "2":
            checkMessage(person)
        elif menuOption == "3":
            readFile("help/helpLogin.txt")
        elif menuOption == "4":
            removeClientFromLoginHandle(person)
            break
        else:
            print("Opção inválida! Tente novamente.")

#############################################################################################
#                               Menu principal do programa.                                 #
#############################################################################################
def menuPrincipal():
    menuOption = -1

    while True:
        print("------------------- Menu Principal -----------------------")
        print("| - 1. Login;                                            |")
        print("| - 2. Registo;                                          |")
        print("| - 3. Menu de Ajuda;                                    |")
        print("| - 4. Sair;                                             |")
        print("----------------------------------------------------------")

        menuOption = input("Seleciona uma opção: ")

        if menuOption == "1":
            login()
        elif menuOption == "2":
            registo()
        elif menuOption == "3":
            readFile("help/helpMain.txt")
        elif menuOption == "4":
            break
        else:
            print("Opção inválida! Tente novamente.")

#############################################################################################
#              Função para verificar se o utilizador já se encontra registado.              #
#############################################################################################
def checkIfUserAlreadyExists(nome):
    for client in clientsRegisted:
        if nome in client:
            return True
    
    return False

#############################################################################################
#              Função para verificar se a password corresponde ao utilizador.               #
#############################################################################################
def checkPasswordLogin(nome, password):
    global clientLoggedIn, clientsRegisted
    for client in clientsRegisted:
        if nome == client[0] and matchHashedText(client[1], password) == True:

            return True

    return False

#############################################################################################
#                             Função para realizar o registo.                               #
#############################################################################################
def registo():
    global clientLoggedIn, clientsRegisted

    nomeRegisto = input("Insere o teu nome para registar: ")

    # Vamos verificar se o utilizador se encontra registado.
    #   Se sim, vai pedir outro nome para este se registar.
    while checkIfUserAlreadyExists(nomeRegisto) == True:
        print("Este nome já se encontra registado!")
        nomeRegisto = input("Insere outro nome: ")

    isPasswordCorrect = -1
    passwordRegisto = getpass.getpass("Insere a tua password: ")
    passwordRegistoConfirmar = getpass.getpass("Confirma a tua password: ")

    # Vamos verificar se o utilizador colocou a mesma password para confirmar
    #   Caso sim, indicamos que é igual e o utilizador não necessita de inserir novamente
    if passwordRegisto == passwordRegistoConfirmar:
        isPasswordCorrect = 1
    
    if len(passwordRegisto) < 8:
        isPasswordCorrect = 0

    # Enquanto as duas passwords não forem iguais, vai pedir ao utilizador para escrever novamente
    while isPasswordCorrect < 1 :

        if isPasswordCorrect == -1:
            print("A password está incorreta!")
        else:
            print("A password possui menos de 8 caracteres!")
        
        passwordRegisto = getpass.getpass("Insere a tua password: ")
        passwordRegistoConfirmar = getpass.getpass("Confirma a tua password: ")
        
        if passwordRegisto == passwordRegistoConfirmar:
            isPasswordCorrect = 1

    # Vamos gerar o valor de hash, juntamente com o "salt" da password
    hashAndSaltGenerated = getHashValue(passwordRegisto, True)

    # Vamos guardar o nome do utilizador, juntamente com o salt e o valor de hash da password.
    writeToFile("registo.txt", nomeRegisto + " | " + hashAndSaltGenerated + "\n", True)
    
    clientsRegisted.append([nomeRegisto, hashAndSaltGenerated])

    cmd = 'mkdir'.split()

    cmd.append("messages/" + str(nomeRegisto))

    subprocess.run(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

#############################################################################################
#                              Função para realizar o login.                                #
#############################################################################################
def login():
    global clientLoggedIn, clientsRegisted

    nomeLogin = input("Insere o teu nome para login: ")

    while checkIfUserAlreadyExists(nomeLogin) == False:
        print("Este nome não se encontra registado!")
        nomeLogin = input("Escreve outro nome: ")

    while checkIfPersonIsAlreadyOnline(nomeLogin) == True:
        print("Este utilizador já se encontra ligado!")
        nomeLogin = input("Escreve outro nome: ")

    passwordLogin = getpass.getpass("Insere a tua password: ")

    while checkPasswordLogin(nomeLogin, passwordLogin) == False:
        print("A password está errada!")
        passwordLogin = getpass.getpass("Insere a tua password: ")

    clientLoggedIn = nomeLogin

    writeToFile("clientsOnline.txt", nomeLogin + "\n", True)

    menuAposLogin(nomeLogin)

#############################################################################################
#                      Função para obter os utilizadores registados.                        #
#############################################################################################
def getClientsRegisted():
    global clientLoggedIn, clientsRegisted

    if fileExists("registo.txt") == True:
        f = open("registo.txt", "r")

        fileLines = f.readlines()

        for line in fileLines:
            stringToSplit = line.split(" | ")

            clientsRegisted.append([stringToSplit[0], stringToSplit[1][:-1]])

def checkIfPersonIsAlreadyOnline(person):

    personIsOnline = False

    if fileExists("clientsOnline.txt") == True:
        file = open("clientsOnline.txt", "r")

        for line in file:
            if line[:-1] == person:
                personIsOnline = True
        
        file.close()

    return personIsOnline

#############################################################################################
#             Função para indicar que o cliente já não se encontra ligado.                  #
#############################################################################################
def removeClientFromLoginHandle(person):
    f = open("clientsOnline.txt", "r+")

    fileLines = f.readlines()
    f.seek(0)

    # Caso a pessoa esteja na lista de utilizadores ligados, vai ser removida da lista, para se realizar o login no futuro.
    for line in fileLines:
        if person != line[:-1]:
            f.write(line)

    f.truncate()

#############################################################################################
#                              Função principal do programa.                                #
#############################################################################################
if __name__ == "__main__":

    # No início do programa, vamos buscar todos os utilizadores registados, para os adicionar a uma lista, iniciando o menu principal
    # Caso o programa crashe (propositadamente ou não), vamos retirar o utilizador que se encontra online (se existir) do ficheiro de clientes online.
    try:
        getClientsRegisted()
        menuPrincipal()
    except Exception as e:
        print("Crash: " + str(e))
        #print("\nNome Atual: " + str(clientLoggedIn))
        if clientLoggedIn != "":         
            removeClientFromLoginHandle(clientLoggedIn)