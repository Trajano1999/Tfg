# Criptosistema de Chor-Rivest

# Juan Manuel Mateos Pérez

# jjj

## Explicación :
# En este programa estamos simulando el envío de información entre dos usuarios. 
# Primero, hacemos de usuario I (diseñador) y generamos a partir del tamaño del mensaje, los valores iniciales m, w y ap, que forman la clave privada.
# A continuación, generamos nuestra clave pública partir de la clave privada desarrollada, para que otro usuario J nos envíe la información. 
# Luego, como usuario J, procederemos con la encriptación del mensaje S = a*x para enviarlo al usuario I.
# Finalmente, como usuario I y diseñador, conociendo las claves privadas, aplicaremos el criptosistema de Merkle-Hellman para obtener el mensaje cifrado
# recibido, comprobando en última instancia si coincidía con el original.

## Ejecución :
# Para ejecutar el programa solo debemos descomentar el código del main que queramos utilizar. Si descomentamos la primera parte, podremos ejecutar el 
# programa 1 vez viendo todos los datos. En cambio, si descomentamos la segunda parte, el programa se ejecuta n veces y solo muestra los fallos cometidos.
# En el primer caso, podemos modificar el valor del tamaño del mensaje (variable tam). Además, podemos comprobar el resultado con valores conocidos añadiendo 
# el mensaje y la clave privada que queramos comprobar en la llamada a la función (unaIteracion). Si no incluimos esos valores, el programa generará otros 
# automáticamente. En el segundo caso, la variable n indica la cantidad de criptosistemas que se van a ejecutar.

import math
import random

#------------------------------------------------------------------------------
# Clase Chor_Rivest
#------------------------------------------------------------------------------

class Chor_Rivest:
    # constructor
    def __init__(self, tamano, mensaje=None, sk=None):
        self.tamano     = tamano
        self.cifrado    = -1
        self.h          =  0
        self.descifrado = -1
        self.errores    = -1

        # genero el mensaje en caso de no recibirlo
        if mensaje is None:
            self.__generaMensaje()
        else:
            self.mensaje = mensaje
            for i in mensaje:
                if i == 1:
                    self.h += 1
        
        # genero la clave privada en caso de no recibirla
        if sk is None:
            self.__generarClavePrivada()
        else:
            self.sk = sk
        
        # genero la clave pública
        self.__generarClavePublica()

    # genera un mensaje aleatorio
    def __generaMensaje(self):
        n = self.tamano
        h = 0
        mensaje = []

        for i in range(n):
            val = random.randint(0, 1)
            if val == 1: 
                h += 1
            mensaje.append(val)

        self.h = h
        self.mensaje = mensaje
    
    # genera la clave privada jjj
    def __generarClavePrivada(self):
        n = self.tamano
        self.sk = n

    # genera la clave pública jjj
    def __generarClavePublica(self):
        n  = self.tamano
        sk = self.sk
        a  = []

        for i in range(0, n):
            a.append((sk[1] * sk[2][i]) % sk[0])
        
        self.pk = a

    # cifra un mensaje
    def cifrar(self):
        q       = self.tamano
        h       = self.h
        pk      = self.pk
        mensaje = self.mensaje
        cifrado = 0

        for i in range(q):
            cifrado += (mensaje[i] * pk[i]) % (q**h - 1)
        
        self.cifrado = cifrado

    # descifra un mensaje jjj
    def descifrar(self):
        q       = self.tamano
        h       = self.h
        sk      = self.sk
        cifrado = self.cifrado

        y_prima = cifrado - (h * sk[3]) % (q**h - 1)

        
        self.res = res

    # calcula el número de fallos del resultado
    def comprobar(self):
        n = self.tamano
        mensaje_original = self.mensaje
        mensaje_obtenido = self.res
        vector_dif = []

        for i in range(n):
            vector_dif.append(abs(mensaje_original[i] - mensaje_obtenido[i]))

        self.errores = sum(vector_dif)

    # aplica todo el criptosistema
    def do(self):
        self.cifrar()
        self.descifrar()
        self.comprobar()

    # muestra los resultados del criptosistema
    def info(self):
        print("Clave privada      :", self.sk)
        print("Clave pública      :", self.pk)
        print("Mensaje original   :", self.mensaje)
        print("Mensaje cifrado    :", self.s)
        print("Mensaje descifrado :", self.res)
        print("Tamaño del mensaje :", self.tamano)
        print("Errores totales    :", self.errores)
        print()

#------------------------------------------------------------------------------
# Datos de salida jjj
#------------------------------------------------------------------------------

# def unaIteracion(tam, mensaje=None, sk=None):
#     if mensaje is not None and sk is not None:
#         merkle_hellman = Merkle_Hellman(tam, mensaje, sk)
#     else:
#         merkle_hellman = Merkle_Hellman(tam)
#     merkle_hellman.do()
#     merkle_hellman.info()

# def variasIteraciones(n):
#     errores_totales = 0

#     print("Iteración \t Tamaño Vector \t Número Errores")
#     for i in range(n):
#         errores = 0
#         print(i+1, end="")
    
#         tam = random.randint(3, 100)
#         print("\t\t", tam, end="")

#         merkle_hellman = Merkle_Hellman(tam)
#         merkle_hellman.do()
        
#         errores += merkle_hellman.errores
#         print("\t\t", errores)
#         errores_totales += errores

#     print("\nErrores totales tras", n, "iteraciones :", errores_totales)
#     print()

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':

    print("\nChor-Rivest")
    print()

    chor_rivest = Chor_Rivest(5)
    chor_rivest.do()
    chor_rivest.info()

    # ---------- descomentar para realizar 1 ejecución aleatoria ----------
    # tam     = random.randint(3, 100)
    # mensaje = [0, 0, 0, 1, 1]
    # sk      = [2113, 988, [3, 42, 105, 249, 495]]
    # unaIteracion(tam)

    # ---------- descomentar para realizar n ejecuciones aleatorias ----------
    # n = 100
    # variasIteraciones(n)
