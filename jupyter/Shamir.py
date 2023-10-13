# Criptoataque de Shamir al criptosistema de Merkle-Hellman

# Juan Manuel Mateos Pérez

import math
import random

#------------------------------------------------------------------------------
# Clase Shamir
#------------------------------------------------------------------------------

class Shamir:
    # constructor
    def __init__(self, pk, s, mensaje):
        self.pk      = pk
        self.s       = s
        self.mensaje = mensaje
        self.res     = mensaje
        self.errores = -1

    # calcula el número de fallos del resultado
    def comprobar(self):
        mensaje_original = self.mensaje
        mensaje_obtenido = self.res
        vector_dif = []

        for i in range(0, len(mensaje_original)):
            vector_dif.append(abs(mensaje_original[i] - mensaje_obtenido[i]))

        self.errores = sum(vector_dif)

    # aplica todo el criptoataque y muestra los resultados
    def do(self):
        self.comprobar()

        print("\tCriptoataque de Shamir")
        print("\tClave pública      : ", self.pk)
        print("\tMensaje original   : ", self.mensaje)
        print("\tMensaje cifrado    : ", self.s)
        print("\tMensaje obtenido   : ", self.res)
        print("\tErrores totales    : ", self.errores)
        print()

#------------------------------------------------------------------------------
# Clase Merkle_Hellman
#------------------------------------------------------------------------------

class Merkle_Hellman:
    # constructor
    def __init__(self, tamano, mensaje=None, sk=None):
        self.tamano  = tamano
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
        lim_inf = 2 ** (2*n + 1) + 1 
        lim_sup = 2 ** (2*n + 2) - 1
        while True:
            m  = random.randint(lim_inf, lim_sup)
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

    # calcula el número de fallos del resultado
    def comprobar(self):
        n = self.tamano
        mensaje_original = self.mensaje
        mensaje_obtenido = self.res
        vector_dif = []

        for i in range(0, n):
            vector_dif.append(abs(mensaje_original[i] - mensaje_obtenido[i]))

        self.errores = sum(vector_dif)

    # aplica todo el criptosistema y muestra los resultados
    def do(self):
        self.cifrar()
        self.descifrar()
        self.comprobar()

        print()
        print("\tCriptosistema de Merkle-Hellman")
        print("\tTamaño del mensaje : ", self.tamano)
        print("\tClave privada      : ", self.sk)
        print("\tClave pública      : ", self.pk)
        print("\tMensaje original   : ", self.mensaje)
        print("\tMensaje cifrado    : ", self.s)
        print("\tMensaje cescifrado : ", self.res)
        print("\tErrores totales    : ", self.errores)
        print()

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':
    # variables Merkle-Hellman
    tam     = 5
    mensaje = [0, 0, 0, 1, 1]
    sk      = [2113, 988, [3, 42, 105, 249, 495]]

    # Merkle-Hellman
    merkle_hellman = Merkle_Hellman(tam)
    merkle_hellman.do()
    
    # variables Shamir
    pk      = merkle_hellman.pk
    s       = merkle_hellman.s
    mensaje = merkle_hellman.mensaje

    # Shamir
    shamir = Shamir(pk, s, mensaje)
    shamir.do()
