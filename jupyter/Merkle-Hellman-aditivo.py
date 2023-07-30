# Criptosistema de Merkle-Hellman (mochila con trampilla aditiva)

## En este programa estamos simulando el envío de información entre dos usuarios. 
# Primero, hacemos de usuario I (diseñador) y generamos a partir del tamaño del mensaje, los valores iniciales m, w y ap, que forman la clave privada.
# A continuación, generamos nuestra clave pública partir de la clave privada desarrollada, para que otro usuario J nos envíe la información. 
# Luego, como usuario J, procederemos con la encriptación del mensaje S = a*x para enviarlo al usuario I.
# Finalmente, como usuario I y diseñador, conociendo las claves privadas, aplicaremos el criptosistema de Merkle-Hellman para obtener el mensaje cifrado
# recibido, comprobando en última instancia si coincidía con el original.

import random

# jjj
def esSC(v):
    s = 0
    for i in range(0, len(v)-1):
        s += v[i]
        if(s >= v[i+1]):
            return False
    return True

#------------------------------------------------------------------------------
# Funciones auxiliares
#------------------------------------------------------------------------------ 

# comprueba si un vector recibido es binario o no
# mensaje : str (mensaje)
def esBinario(mensaje):
    for caracter in mensaje:
        if caracter not in {'0', '1'}:
            return False
    return True

# genera un vector de enteros donde cada valor es la cifra correspondiente del número recibido 
# numero : str (valor)
def generarVector(numero):
    vector = [int(digito) for digito in numero]
    return vector

# lee y comprueba el tamaño del mensaje
def lecturaTamano():
    mensaje_error = "Error: Debe introducirse un número natural."

    print("\nIntroduce la longitud del mensaje : ", end="")
    longitud_mensaje = input()

    if (not longitud_mensaje.isdigit()) or int(longitud_mensaje) <= 0:
        print(mensaje_error)
        exit(-1)
    else:
        longitud_mensaje = int(longitud_mensaje)

    return longitud_mensaje

# lee y comprueba el mensaje recibido
# n : int (tamaño del mensaje)
def lecturaMensaje(n):
    mensaje_error_binario = "Error: Debe introducirse un valor en binario."
    mensaje_error_longitud = "Error: Debe introducirse un mensaje de longitud " + str(n) + "."

    print("\nIntroduzca el mensaje : ", end = "")
    mensaje = input()

    if not esBinario(mensaje):
        print(mensaje_error_binario)
        exit(-1)

    if len(mensaje) != n:
        print(mensaje_error_longitud)
        exit(-1)

    return generarVector(mensaje)

#------------------------------------------------------------------------------
# Funciones del criptosistema
#------------------------------------------------------------------------------ 

# calcula el máximo común divisor de dos valores a y b
# a : int (primer valor)
# b : int (segundo valor)
def mcd(a, b):
    while b != 0:
        a, b = b, a % b
    return abs(a)

# genera una sucesión supercreciente de n elementos
# n : int (tamaño de la sucesión)
def generaSucesionSC(n):
    sucesion = []

    for i in range(1, n+1):
        ap = random.randint((2**(i-1)-1) * 2**n + 1, 2**(i-1) * (2**n))
        sucesion.append(ap)

    return sucesion

# genera un vector formado por m, w y ap (en ese orden)
# n : int (tamaño del mensaje)
def generacionClavePriv(n):
    cp = []

    # generamos los valores coprimos (w es invertible módulo m)
    while True:
        m  = 8443 # random.randint( 2**((2*5) + 1) + 1, 2**((2*n) + 2) - 1 )                       # jjj
        wp = random.randint(2, m-2)
        w  = int(wp / mcd(wp, m))
        if mcd(m, w) == 1:
            break
    
    cp.append(m)
    cp.append(w)

    # generamos la sucesión supercreciente
    ap = generaSucesionSC(n)
    cp.append(ap)

    return cp

# genera el vector a (clave pública) a partir de las claves privadas
# cp : vector de claves privadas
def generacionClavePub(cp):
    a = []
    for i in range(0, len(cp[2])):
        a.append((cp[1] * cp[2][i]) % cp[0])
    return a

# encripta el mensaje recibido con la clave pública
# mensaje : vector int (mensaje binario)
def encriptarMensaje(mensaje, cpub):
    s = 0
    for i in range(0, len(cpub)):
        s += mensaje[i] * cpub[i]
    return s

# aplica el criptosistema de Merkle-Hellman (aditivo)
# cp : vector de claves privadas
# s : int (mensaje encriptado)
def merkleHellman(cp, s):
    res = []
    
    # cálculo del inverso modular de w módulo m, esto es, el inverso de w módulo m
    inv_w = pow(cp[1], cp[0]-2, cp[0])

    # cálculo de sp
    sp = (inv_w * s) % cp[0]

    # cálculo de resultado
    suma = 0
    for i in range(len(cp[2])-1, -1, -1):
        suma += cp[2][i]
        if(sp >= suma):
            res.insert(0, 1)
        else:
            suma -= cp[2][i]
            res.insert(0, 0)
        
    # devolvemos el vector resultado
    return res

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':

    # mensaje del usuario J
    tamano_mensaje = 5 #lecturaTamano() jjj

    # generación de claves privadas
    claves_privadas = generacionClavePriv(tamano_mensaje)
    #print("Cprivada :", claves_privadas)

    # generación de claves públicas
    clave_publica = generacionClavePub(claves_privadas)
    #print("Cpublica :", clave_publica)
    
    # lectura del mensaje original
    #mensaje = lecturaMensaje(tamano_mensaje) jjj
    mensaje = []
    for i in range(0, tamano_mensaje):
        mensaje.append(random.randint(0,1))

    # encriptación del mensaje
    mensaje_encriptado = encriptarMensaje(mensaje, clave_publica)

    # desencriptación del mensaje
    mensaje_desencriptado = merkleHellman(claves_privadas, mensaje_encriptado)

    print("mensaje encriptado    :", mensaje_encriptado)
    print("mensaje introducido   :", mensaje)
    print("mensaje desencriptado :", mensaje_desencriptado)
    print()
    print("lm :", len(mensaje), "lmd :", len(mensaje_desencriptado))

    vector_dif = []
    for i in range(0, len(mensaje)):
        vector_dif.append(abs(mensaje[i] - mensaje_desencriptado[i]))
    print("Diferencia :", sum(vector_dif))
    print()
