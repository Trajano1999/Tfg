# Criptosistema de Merkle-Hellman

## En este programa estamos simulando el envío de información entre dos usuarios. 
# Primero hacemos de usuario "diseñador" y por tanto, debemos elegir los valores iniciales m, w y ap, para generar nuestra clave pública a 
# a partir de ap, para que otro usuario J nos envíe la información. Como también hacemos de usuario J, la información la almacenaremos en un
# vector x y comprobaremos al final del programa si lo que queríamos enviar es igual al resultado obtenido por el criptosistema.
# Como usuario J que somos, a partir de la clave pública a, vamos a generar S = a*x, que es el mensaje cifrado, y se lo haremos llegar al 
# diseñador. Finalmente, siendo diseñador, y conociendo m, w, ap, a y s, aplicamos el criptosistema para obtener el mensaje que hemos 
# recibido, comprobando en última instancia si coincide con el original.

#------------------------------------------------------------------------------
# Funciones auxiliares
#------------------------------------------------------------------------------ 

# genera un vector ordenado donde cada posición es la cifra correspondiente del número recibido
def generarVector(numero):
    vector = [int(digito) for digito in numero]
    return vector

# comprueba si un vector recibido es binario o no
def esBinario(vector):
    for elemento in vector:
        if elemento != 0 and elemento != 1:
            return False
    return True

# muestra y realiza la lectura de los datos
def mensajeInicio(ap):
    print("\nIntroduce el mensaje que quieres enviar. Debe ser un mensaje en binario de longitud", len(ap))
    print("Mensaje : ", end="")
    mensaje = input()

    if not mensaje.isdigit():
        print("Error: El valor introducido no es un número válido.")
        raise SystemExit

    return mensaje
    
# comprueba que el vector recibido sea binario y tenga una longitud determinada 
def mensajeCorrecto(mensaje, ap):
    if len(mensaje) != len(ap):
        print("Error: Longitud inadecuada.")
        return False
    
    if not esBinario(mensaje):
        print("Error: Deben ser valores binarios.")
        return False
    
    return True

#------------------------------------------------------------------------------
# Funciones del criptosistema
#------------------------------------------------------------------------------ 

# genera el vector a (clave pública)
def generacionA(ap, w, m):
    a = []
    for i in range(0, len(ap)):
        a.append((w * ap[i]) % m)
    return a

# aplica el criptosistema de Merkle-Hellman
def merkleHellman(m, w, ap, s):
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
    
    # valores iniciales diseñador
    m  = 8443
    w  = 2550                           # invertible módulo m
    ap = [171, 196, 457, 1191, 2410]    # sucesión supercreciente
    
    # valores generados por el diseñador
    a = generacionA(ap, w, m)           # clave pública

    # mensaje del usuario J
    mensaje_inicial = mensajeInicio(ap)
    x = generarVector(mensaje_inicial)
    
    # comprobamos que el mensaje cumpla las condiciones
    if not mensajeCorrecto(x, ap):
        raise SystemExit
    
    # generación del mensaje del usuario J cifrado 
    s = 0
    for i in range(0, len(a)):
        s += x[i] * a[i]
    
    # aplicamos Merkle-Hellamn
    print()
    print("Mensaje inicial  :", x)
    mensaje_final = merkleHellman(m, w, ap, s)
    print("Mensaje obtenido :", mensaje_final)
    print()
