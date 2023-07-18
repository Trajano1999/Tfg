# Criptosistema de Merkle-Hellman

## Descripción del problema de la mochila:
#   Sea S el tamaño total de una mochila unidimensional y un vector a = (a1, ... , an)
#   de naturales positivos, queremos encontrar un vector x = (x1, ... , xn) con xi en {0,1}, 
#   tal que S = a*x = Sum (ai*xi), siendo * el producto escalar. 
#   En caso de que no exista esa igualdad, buscamos quedarnos lo más cerca posible.

# linea que añadir en caso de fallo en el for de Merkle Hellman
# print("En la iteracion", i,"el valor de la suma es", suma, "y el de sp es", sp)

#------------------------------------------------------------------------------
# Funciones
#------------------------------------------------------------------------------ 

# genera el vector a
def generacionA(ap, w, m):
    a = []
    for i in range(0, len(ap)):
        a.append((w * ap[i]) % m)
    return a

# suma los elementos de a que indica merhel
def sumaMerhel(merhel, a):
    suma_merhel = 0
    for i in range(0, len(a)):
        if(merhel[i] == 1):
            suma_merhel += a[i]
    return suma_merhel

# aplica Merkle-Hellman
def merkleHellman(m, w, ap, a, s):
    res = []
    
    # cálculo del inverso modular de w módulo m, esto es, el inverso de w módulo m
    inv_w = pow(w, m-2, m)

    # cálculo de sp
    sp = (inv_w * s) % m

    # cálculo de resultado
    suma = 0
    for i in range(len(ap)-1, -1, -1):
        suma += ap[i]
        if(sp >= suma):
            res.insert(0, 1)
        else:
            suma -= ap[i]
            res.insert(0, 0)
        
    # devolvemos el vector resultado
    return res

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':
    
    # valores iniciales
    s = 15115
    ap = [171, 196, 457, 1191, 2410]    # sucesión supercreciente
    
    # valores que escogemos (coprimos)
    m = 8443
    w = 2550    # invertible módulo m
    
    # valores generados
    a = generacionA(ap, w, m)   # clave pública

    # aplicamos Merkle-Hellman
    mensaje = merkleHellman(m, w, ap, a, s)
    print("\nMensaje obtenido :", mensaje)
    print()
    print("Valor de S a alcanzar   :", s)
    print("Valor de Merkle-Hellman :", sumaMerhel(mensaje, a), ", en el intervalo [0 - 20788]")
    print()
        