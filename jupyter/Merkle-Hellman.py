# Criptosistema de Merkle-Hellman

# Juan Manuel Mateos Pérez

## En este programa estamos simulando el envío de información entre dos usuarios. 
# Primero, hacemos de usuario I (diseñador) y generamos a partir del tamaño del mensaje, los valores iniciales m, w y ap, que forman la clave privada.
# A continuación, generamos nuestra clave pública partir de la clave privada desarrollada, para que otro usuario J nos envíe la información. 
# Luego, como usuario J, procederemos con la encriptación del mensaje S = a*x para enviarlo al usuario I.
# Finalmente, como usuario I y diseñador, conociendo las claves privadas, aplicaremos el criptosistema de Merkle-Hellman para obtener el mensaje cifrado
# recibido, comprobando en última instancia si coincidía con el original.

import math
import random

#------------------------------------------------------------------------------
# Clase Merkle_Hellman
#------------------------------------------------------------------------------

class Merkle_Hellman:
    # constructor
    def __init__(self, tamano, num_it, mensaje=None, sk=None):
        self.tamano  = tamano
        self.num_it  = num_it
        self.s       = -1
        self.res     = -1
        self.errores = -1

        # genero el mensaje en caso de no recibirlo
        if mensaje is None:
            self.__generaMensaje() 
        else:
            self.mensaje = mensaje
        
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
        mensaje = []

        for i in range(0, n):
            mensaje.append(random.randint(0,1))

        self.mensaje = mensaje

    # genera una sucesión supercreciente
    def __generaSucesionSC(self):
        n = self.tamano
        sucesion = []

        for i in range(1, n+1):
            ap = random.randint(((2**(i-1))-1) * (2**n) + 1, (2**(i-1)) * (2**n))
            sucesion.append(ap)

        return sucesion
    
    # genera la clave privada
    def __generarClavePrivada(self):
        n = self.tamano

        # generamos la sucesión supercreciente
        ap = self.__generaSucesionSC()
        sum_ap = sum(ap)

        # generamos el valor m
        while True:
            m  = random.randint((2**((2*n) + 1)) + 1, (2**((2*n) + 2)) - 1)
            if m > sum_ap:                                          
                break
        
        # generamos el valor w (invertible módulo m)
        while True:
            wp = random.randint(2, m-2)
            w  = int(wp / math.gcd(wp, m))
            if math.gcd(m, w) == 1:
                break
                
        sk = [m, w, ap]
        self.sk = sk

    # genera la clave pública
    def __generarClavePublica(self):
        n  = self.tamano
        sk = self.sk
        a  = []

        for i in range(0, n):
            a.append((sk[1] * sk[2][i]) % sk[0])
        
        self.pk = a

    # cifra un mensaje
    def cifrar(self):
        n       = self.tamano
        pk      = self.pk
        mensaje = self.mensaje
        s       = 0

        for i in range(0, n):
            s += mensaje[i] * pk[i]
        
        self.s = s

    # descifra un mensaje
    def descifrar(self):
        n   = self.tamano
        sk  = self.sk
        s   = self.s
        res = [0 for i in range(n)]
        
        # calculamos el inverso modular de w módulo m
        inv_w = pow(sk[1], -1, sk[0])

        # calculamos sp
        sp = (inv_w * s) % sk[0]

        # calculamos el resultado
        for i in range(n):
            if sp >= sk[2][n - 1 - i]:
                sp -= sk[2][n - 1 - i]
                res[n - 1 - i] = 1
        
        self.res = res

    # comprobamos el resultado
    def comprobacion(self):
        n = self.tamano
        mensaje_original = self.mensaje
        mensaje_obtenido = self.res
        vector_dif = []

        for i in range(0, n):
            vector_dif.append(abs(mensaje_original[i] - mensaje_obtenido[i]))

        self.errores = sum(vector_dif)

    # aplica todo el criptosistema
    def do(self):
        self.cifrar()
        self.descifrar()
        self.comprobacion()

        print()
        print("\tTamaño             : ", self.tamano)
        print("\tNúmero Iteraciones : ", self.num_it)
        print("\tClave Privada      : ", self.sk)
        print("\tClave Pública      : ", self.pk)
        print("\tMensaje Cifrado    : ", self.s)
        print("\tMensaje Original   : ", self.mensaje)
        print("\tMensaje Descifrado : ", self.res)
        print("\tErrores            : ", self.errores)
        print()

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':
    tam     = 5
    it      = 0
    mensaje = [0, 0, 0, 1, 1]
    sk      = [2113, 988, [3, 42, 105, 249, 495]]

    merkle_hellman = Merkle_Hellman(tam, it)
    merkle_hellman.do()
