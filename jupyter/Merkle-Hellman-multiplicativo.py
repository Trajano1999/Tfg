# Criptosistema de Merkle-Hellman (mochila con trampilla multiplicativa)

## En este programa estamos simulando el envío de información entre dos usuarios. 
# Primero hacemos de usuario "diseñador" y por tanto, debemos elegir los valores iniciales m, b y ap, para generar nuestra clave pública a 
# a partir de ap, para que otro usuario J nos envíe la información. Como también hacemos de usuario J, la información la almacenaremos en un
# vector x y comprobaremos al final del programa si lo que queríamos enviar es igual al resultado obtenido por el criptosistema.
# Como usuario J que somos, a partir de la clave pública a, vamos a generar S = a*x, que es el mensaje cifrado, y se lo haremos llegar al 
# diseñador. Finalmente, siendo diseñador, y conociendo m, b, ap y s, aplicamos el criptosistema para obtener el mensaje que hemos 
# recibido, comprobando en última instancia si coincide con el original.

# IMPORTANTE : este programa solo se puede ejecutar indicandole el valor de la clave pública directamente, es decir, no puede calcularla, 
# por lo que no recibe cualquier mensaje en binario por la entrada.
# Sin embargo, si que está programado tal método de obtención de la clave pública a a partir de a'. El problema es que los valores que hay que 
# afrontar son demasiado grandes. Por ejemplo, tomando los valores del programa (que son los del artículo original de Merkle-Hellman), solo para
# calcular el primer valor de a, que es 80, a partir de un vector a' sencillo, se deben realizar 9.370667523227057e+166 iteraciones.

from math import log

#------------------------------------------------------------------------------
# Funciones del criptosistema
#------------------------------------------------------------------------------ 

# comprueba si un número recibido es entero o no
def esEntero(n):
    return n == int(n)

# genera el vector a (clave pública)
def generacionA(ap, b, m):
    res = []
    for a in ap:
        n = 0.1
        y = 0
        while(not esEntero(n)):
            n = log(y * m + a) / log(b)
            y += 1
        res.append(n)        

    return res

# aplica el criptosistema de Merkle-Hellman
def merkleHellmanMultiplicativo(m, b, ap, s):
    res = [0] * len(ap)
    
    # cálculo de sp
    sp = (b**s) % m

    # cálculo de resultado
    for i in range(0, len(ap)):
        if sp % ap[i] == 0:
           res[i] = 1
           sp /= ap[i]
        
    # devolvemos el vector resultado
    return res

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':
    
    # valores iniciales diseñador
    m  = 257
    b  = 131
    ap = [2, 3, 5, 7]               # valores relativamente primos
    
    # valores generados por el diseñador
    #a = generacionA(ap, b, m)
    a = [80, 183, 81, 195]

    # mensaje del usuario J
    x = [0, 1, 1, 0]
    
    # generación del mensaje del usuario J cifrado 
    s = 0
    for i in range(0, len(a)):
        s += x[i] * a[i]
    
    # aplicamos Merkle-Hellamn
    print()
    print("Mensaje inicial  :", x)
    mensaje_final = merkleHellmanMultiplicativo(m, b, ap, s)
    print("Mensaje obtenido :", mensaje_final)
    print()
