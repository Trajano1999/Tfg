# Criptosistema de Merkle-Hellman iterativo

# Juan Manuel Mateos Pérez

## Explicación :
# En este programa estamos simulando el envío de información entre dos usuarios. 
# Primero, hacemos de usuario I (diseñador) y generamos a partir del tamaño del mensaje, los valores iniciales m, w y ap, que forman la clave privada,
# aplicando tantas iteraciones como se requieran.
# A continuación, generamos nuestra clave pública partir de la clave privada desarrollada, para que otro usuario J nos envíe la información. 
# Luego, como usuario J, procederemos con la encriptación del mensaje S = a*x para enviarlo al usuario I.
# Finalmente, como usuario I y diseñador, conociendo las claves privadas, aplicaremos el criptosistema de Merkle-Hellman para obtener el mensaje cifrado
# recibido, comprobando en última instancia si coincidía con el original.

## Ejecución :
# Para ejecutar el programa, solo debemos descomentar el código del main que queramos utilizar:
# (1) Si descomentamos la primera parte, podremos ejecutar el programa 1 vez y veremos todos los datos necesarios. Asimismo, podemos modificar el valor
# del tamaño del mensaje (variable tam) y el número de iteraciones de la clave privada (variable it). Además, podemos comprobar el resultado con valores
# conocidos añadiendo el mensaje y la clave privada que queramos comprobar en la llamada a la función (unaIteracion). Si no incluimos estos valores, el
# programa generará otros automáticamente.
# (2) Si por otro lado descomentamos la segunda parte, el programa se ejecutará n veces y mostrará un desglose de iteraciones, tamaños y errores
# cometidos. En este caso podemos modificar la variable n, que indica la cantidad de criptosistemas que se van a ejecutar.

import math
import random
import time

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

        for i in range(n):
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
        it_reales  = self.it_done
        it_totales = self.num_it
        sk         = self.sk
        p          = 0

        while it_totales > it_reales:
            sucesion = []

            # calculamos el inverso multiplicativo de w módulo m
            u = pow(sk[p][1], -1, sk[p][0])

            # genera la sucesión
            for i in sk[p][2]:
                sucesion.append((i * u) % sk[p][0])

            # generamos el valor m
            tope = sum(sucesion)
            m = tope + random.randint(1, tope)
                    
            # generamos el valor w (invertible módulo m)
            while True:
                wp  = random.randint(2, m-2)
                gcd = math.gcd(m, wp)
                w   = wp // gcd
                if math.gcd(m, w) == 1:
                    break

            it_reales += 1
            p += 1
            self.sk.append([m, w, sucesion])
        
        self.it_done = it_reales

        # generamos la clave pública
        sucesion = []
        u = pow(sk[p][1], -1, sk[p][0])
        for i in sk[p][2]:
            sucesion.append((i * u) % sk[p][0])
        self.pk = sucesion
    
    # genera la clave pública
    def __generarClavePublica(self):
        n  = self.tamano
        sk = self.sk[len(self.sk) - 1]
        a  = []

        for i in range(n):
            a.append((sk[1] * sk[2][i]) % sk[0])
        
        self.pk = a

    # cifra un mensaje
    def cifrar(self):
        n       = self.tamano
        pk      = self.pk
        mensaje = self.mensaje
        s       = 0

        for i in range(n):
            s += mensaje[i] * pk[i]
        
        self.s = s

    # descifra un mensaje
    def descifrar(self):
        n      = self.tamano
        sk     = self.sk
        s      = self.s
        num_it = self.num_it
        res    = [0 for i in range(n)]
        p      = len(sk) - 1

        if num_it == 0:
            # calculamos el inverso multiplicativo de w módulo m
            inv_w = pow(sk[0][1], -1, sk[0][0])

            # calculamos sp
            sp = (inv_w * s) % sk[0][0]
        else:
            while p >= 0:
                sp = (s * sk[p][1]) % sk[p][0]
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
        print("Clave pública      :", self.pk)
        print("Clave privada      :", self.sk)
        print("Mensaje original   :", self.mensaje)
        print("Mensaje cifrado    :", self.s)
        print("Mensaje descifrado :", self.res)
        print("Tamaño del mensaje :", self.tamano)
        print("Número iteraciones :", self.it_done)
        print("Errores totales    :", self.errores)
        print()

#------------------------------------------------------------------------------
# Datos de salida
#------------------------------------------------------------------------------

# ejecuta y muestra los datos tras aplicar una iteración
def unaIteracion(tam, it, mensaje=None, sk=None):
    if mensaje is not None and sk is not None:
        merkle_hellman = Merkle_Hellman(tam, it, mensaje, sk)
    else:
        merkle_hellman = Merkle_Hellman(tam, it)
    merkle_hellman.do()
    merkle_hellman.info()

# ejecuta y muestra los datos tras aplicar n iteraciones
def variasIteraciones(n):
    errores_totales = 0

    print("Iteración \t Tamaño Vector \t Número Iteraciones \t Número Errores")
    for i in range(n):
        errores = 0
        print(i+1, end="")
    
        tam = random.randint(3, 100)
        print("\t\t", tam, end="")

        it  = random.randint(0, 3)
        print("\t\t", it, end="")
        
        merkle_hellman = Merkle_Hellman(tam, it)
        merkle_hellman.do()
        
        errores += merkle_hellman.errores
        print("\t\t\t", errores)
        errores_totales += errores

    print("\nErrores totales tras", n, "iteraciones :", errores_totales)
    print()

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':

    print("\nCriptosistema de Merkle-Hellman iterativo")
    print()

    # ---------- descomentar para realizar 1 ejecución aleatoria ----------
    # tam     = random.randint(3, 100)
    # it      = random.randint(0, 3)
    # mensaje = [0, 0, 0, 1, 1]
    # sk      = [2113, 988, [3, 42, 105, 249, 495]]
    # unaIteracion(tam, it)

    # ---------- descomentar para realizar n ejecuciones aleatorias ----------
    # n = 100
    # variasIteraciones(n)
