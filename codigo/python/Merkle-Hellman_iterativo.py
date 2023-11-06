# Criptosistema de Merkle-Hellman iterativo

# Juan Manuel Mateos Pérez

## Explicación :
# En este programa estamos simulando el envío de información entre dos usuarios. 
# Primero, hacemos de usuario I (diseñador) y generamos a partir del tamaño del mensaje, los valores iniciales m, w y ap, que forman la clave privada, y
# aplicaremos tantas iteraciones como se requieran.
# A continuación, generamos nuestra clave pública partir de la clave privada desarrollada, para que otro usuario J nos envíe la información. 
# Luego, como usuario J, procederemos con la encriptación del mensaje S = a*x para enviarlo al usuario I.
# Finalmente, como usuario I y diseñador, conociendo las claves privadas, aplicaremos el criptosistema de Merkle-Hellman para obtener el mensaje cifrado
# recibido, comprobando en última instancia si coincidía con el original.

## Ejecución :
# Para ejecutar el programa solo debemos modificar el valor de tamaño del mensaje en el main (variable tam) y el número de iteraciones de la clave 
# privada (variable it). Además, podemos comprobar el resultado con valores conocidos añadiendo el mensaje y la clave privada que queramos comprobar 
# en la llamada al constructor. Si no incluimos esos valores, el programa generará otros automáticamente.

import math
import random

import time # jjj

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
        self.it_done = 0
        self.sk      = []

        # genero el mensaje en caso de no recibirlo
        if mensaje is None:
            self.__generaMensaje()
        else:
            self.mensaje = mensaje
        
        # genero la clave privada en caso de no recibirla
        if sk is None:
            self.__generarClavePrivada()
        else:
            self.sk.append(sk)

        # genero la clave pública
        self.__generarClavePublica()

        # iteramos la clave privada si es necesario
        if self.num_it > self.it_done:
            self.__iterarClavePrivada()

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
            wp  = random.randint(2, m-2)
            gcd = math.gcd(m, wp)
            w   = wp // gcd
            if math.gcd(m, w) == 1:
                break
                
        sk = [m, w, ap]
        self.sk.append(sk)

    # realiza diversas iteraciones sobre la clave privada
    def __iterarClavePrivada(self):
        n          = self.tamano
        it_reales  = self.it_done
        it_totales = self.num_it

        while it_totales > it_reales:
            # genera la sucesión
            ap = self.pk

            # generamos el valor m
            lim_inf = 2 ** (2*n + 1) + 1
            lim_sup = 2 ** (2*n + 2) - 1
            m  = random.randint(lim_inf, lim_sup)
                    
            # generamos el valor w (invertible módulo m)
            while True:
                wp  = random.randint(2, m-2)
                gcd = math.gcd(m, wp)
                w   = wp // gcd
                if math.gcd(m, w) == 1:
                    break

            it_reales += 1
            sk = [m, w, ap]
            self.sk.append(sk)
            self.__generarClavePublica()

        self.it_done = it_reales   
    
    # genera la clave pública
    def __generarClavePublica(self):
        n  = self.tamano
        sk = self.sk[len(self.sk) - 1]
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
        n         = self.tamano
        sk        = self.sk
        s         = self.s
        res       = [0 for i in range(n)]
        p         = len(sk) - 1

        while p >= 0:
            # calculamos el inverso modular de w módulo m
            inv_w = pow(sk[p][1], -1, sk[p][0])

            # calculamos sp
            sp = (inv_w * s) % sk[p][0]

            # jjj
            # print()
            # print("p    :", p)
            # print("sk   :", sk[p])
            # print("inv  :", inv_w)
            # print("s    :", s)
            # print("sp   :", sp)
            # time.sleep(1)

            s = sp
            p -= 1

        # calculamos el resultado
        for i in range(n):
            if sp >= sk[0][2][n - 1 - i]:
                sp -= sk[0][2][n - 1 - i]
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
        print("\tTamaño del mensaje :", self.tamano)
        print("\tNum it solicitadas :", self.num_it)
        print("\tNum it realizadas  :", self.it_done)
        print("\tClave privada      :", self.sk)
        print("\tClave pública      :", self.pk)
        print("\tMensaje original   :", self.mensaje)
        print("\tMensaje cifrado    :", self.s)
        print("\tMensaje descifrado :", self.res)
        print("\tErrores totales    :", self.errores)
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

    # jjj
    # sumas = 0
    # for i in range(0, 100):
    #    merkle_hellman = Merkle_Hellman(tam, it)
    #    merkle_hellman.do()
    #    sumas += merkle_hellman.errores
    #    print(i)
    # print("Errores totales de 100 :", sumas)

# jjj 
# [[2113, 988, [3, 42, 105, 249, 495]], [2882, 343, [851, 1349, 203, 904, 957]], [3154, 123, [811, 1587, 461, 1698, 2585]]]
