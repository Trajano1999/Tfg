# Criptosistema de Merkle-Hellman básico

# Juan Manuel Mateos Pérez

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
            wp  = random.randint(2, m-2)
            gcd = math.gcd(m, wp)
            w   = wp // gcd
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
        
        # calculamos el inverso multiplicativo de w módulo m
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
# Datos de salida
#------------------------------------------------------------------------------

def unaIteracion(tam, mensaje=None, sk=None):
    if mensaje is not None and sk is not None:
        merkle_hellman = Merkle_Hellman(tam, mensaje, sk)
    else:
        merkle_hellman = Merkle_Hellman(tam)
    merkle_hellman.do()
    merkle_hellman.info()

def variasIteraciones(n):
    errores_totales = 0

    print("Iteración \t Tamaño Vector \t Número Errores")
    for i in range(n):
        errores = 0
        print(i+1, end="")
    
        tam = random.randint(3, 100)
        print("\t\t", tam, end="")

        merkle_hellman = Merkle_Hellman(tam)
        merkle_hellman.do()
        
        errores += merkle_hellman.errores
        print("\t\t", errores)
        errores_totales += errores

    print("\nErrores totales tras", n, "iteraciones :", errores_totales)
    print()

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':

    print("\nMerkle-Hellman básico")
    print()

    # ---------- descomentar para realizar 1 ejecución aleatoria ----------
    # tam     = random.randint(3, 100)
    # mensaje = [0, 0, 0, 1, 1]
    # sk      = [2113, 988, [3, 42, 105, 249, 495]]
    # unaIteracion(tam)

    # ---------- descomentar para realizar n ejecuciones aleatorias ----------
    # n = 100
    # variasIteraciones(n)
