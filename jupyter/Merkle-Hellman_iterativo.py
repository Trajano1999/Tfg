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
# Funciones Auxiliares
#------------------------------------------------------------------------------

# comprueba si un número es o no primo (jjj quitar)
def es_primo(numero):
    if numero <= 1:
        return False
    if numero <= 3:
        return True

    # eliminamos los múltiplos de 2 y 3
    if numero % 2 == 0 or numero % 3 == 0:
        return False

    # comprobamos el resto de factores primos
    i = 5
    while i * i <= numero:
        if numero % i == 0 or numero % (i + 2) == 0:
            return False
        i += 6

    return True

# lee y comprueba el tamaño del mensaje
def lecturaTamano():
    mensaje_error = "Error: Debe introducirse un número natural."

    print("\nIntroduce la longitud del mensaje (recomendable menor a 25 por t.computación): ", end="")
    longitud_mensaje = input()

    if (not longitud_mensaje.isdigit()) or int(longitud_mensaje) <= 0:
        print(mensaje_error)
        exit(-1)
    else:
        longitud_mensaje = int(longitud_mensaje)

    return longitud_mensaje

#------------------------------------------------------------------------------
# Clase Merkle_Hellman
#------------------------------------------------------------------------------

class Merkle_Hellman:
    # constructor
    def __init__(self, tamano, num_it, mensaje=None, sk=None):
        self.tamano         = tamano
        self.num_it_pedidas = num_it
        self.s             = -1
        self.res           = -1
        self.errores       = -1
        self.num_it_reales = +1

        # genero el mensaje en caso de no recibirlo
        if mensaje is None:
            self.__generarMensaje() 
        else:
            self.mensaje = mensaje
        
        # genera la clave privada en caso de no recibirla
        if sk is None:
            self.__generarClavePrivada()
        else:
            self.sk = sk
            if self.num_it_pedidas > 1: 
                self.__iterarClavePrivada()
        
        # genero la clave pública
        self.__generarClavePublica()

    # genera un mensaje aleatorio
    def __generarMensaje(self):
        n = self.tamano
        mensaje = []

        for i in range(0, n):
            mensaje.append(random.randint(0,1))

        self.mensaje = mensaje

    # genera una sucesión supercreciente
    def __generarSucesionSC(self):
        n = self.tamano
        sucesion = []

        for i in range(1, n+1):
            ap = random.randint(((2**(i-1))-1) * (2**n) + 1, (2**(i-1)) * (2**n))
            sucesion.append(ap)

        return sucesion        

    # genera la clave privada inicial
    def __generarClavePrivada(self):
        n = self.tamano

        # genera la sucesión
        ap = self.__generarSucesionSC()
        sum_ap = sum(ap)

        # generamos el valor m
        while True:
            m  = random.randint((2**((2*n) + 1)) + 1, (2**((2*n) + 2)) - 1)     # jjj tiene que haber un fallo aquí por lo de ser primo
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

        if self.num_it_pedidas > 1: 
            self.__iterarClavePrivada()

    # itera la clave privada
    def __iterarClavePrivada(self):
        n          = self.tamano
        it_reales  = self.num_it_reales
        
        while self.num_it_pedidas > it_reales:
            # genera la sucesión
            self.__generarClavePublica()
            ap = self.pk
            sum_ap = sum(ap)

            # generamos el valor m
            while True:
                m  = random.randint((2**((2*n) + 1)) + 1, (2**((2*n) + 2)) - 1)     # jjj el max valor del intervalo es 4095 y la suma es mayor a 5000
                if m > sum_ap:                                      
                    break
                    
            # generamos el valor w (invertible módulo m)
            while True:
                wp = random.randint(2, m-2)
                w  = int(wp / math.gcd(wp, m))
                if math.gcd(m, w) == 1:
                    break

            it_reales += 1
            sk = [m, w, ap]
            self.sk = sk

        self.num_it_reales = it_reales

    # genera la clave pública
    def __generarClavePublica(self):
        sk = self.sk
        a  = []

        for i in range(0, len(sk[2])):
            a.append((sk[1] * sk[2][i]) % sk[0])
        
        self.pk = a

    # cifra un mensaje
    def __cifrar(self):
        pk      = self.pk
        mensaje = self.mensaje
        s = 0

        for i in range(0, len(pk)):
            s += mensaje[i] * pk[i]
        
        self.s = s

    # descifra un mensaje
    def __descifrar(self):
        sk  = self.sk
        s   = self.s
        res = []
        
        # calculamos el inverso modular de w módulo m
        inv_w = pow(sk[1], sk[0]-2, sk[0])

        # calculamos sp
        sp = (inv_w * s) % sk[0]

        # calculamos el resultado
        suma = 0
        for i in range(len(sk[2])-1, -1, -1):
            suma += sk[2][i]
            if(sp >= suma):
                res.insert(0, 1)
            else:
                suma -= sk[2][i]
                res.insert(0, 0)
        
        self.res = res

    # comprobamos el resultado
    def __comprobar(self):
        mensaje_original = self.mensaje
        mensaje_obtenido = self.res
        vector_dif = []

        for i in range(0, len(mensaje_original)):
            vector_dif.append(abs(mensaje_original[i] - mensaje_obtenido[i]))

        self.errores = sum(vector_dif)

    # aplica todo el criptosistema
    def do(self):
        self.__cifrar()
        self.__descifrar()
        self.__comprobar()

        print("\n\tTamaño del vector             : ", self.tamano)
        print("\tNúmero iteraciones pedidas    : ", self.num_it_pedidas)
        print("\tNúmero iteraciones realizadas : ", self.num_it_reales)

        print("\n\tGeneramos la clave privada...")
        print("\tClave Privada : ", self.sk)

        print("\n\tGeneramos la clave pública...")
        print("\tClave Pública : ", self.pk)

        print("\n\tGeneramos de un mensaje aleatorio...")
        print("\tMensaje Original : ", self.mensaje)

        print("\n\tCiframos el mensaje...")
        print("\tMensaje Cifrado : ", self.s)

        print("\n\tDesciframos el mensaje...")
        print("\tMensaje Descifrado : ", self.res)

        print("\n\tCalculamos los errores cometidos...")
        print("\tErrores : ", self.errores)
        print()

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':

    # jjj leemos el tamaño del mensaje
    #tamano_mensaje = lecturaTamano()
    
    tam     = 5
    it      = 1
    mensaje = [0, 0, 0, 1, 1]
    sk      = [2113, 988, [3, 42, 105, 249, 495]]

    merkle_hellman = Merkle_Hellman(tam, it)
    merkle_hellman.do()
