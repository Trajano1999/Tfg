# Programas del TFG

Este directorio contiene el código de los programas implementados en el TFG.

## Descripción

Para su explicación, subdividos el directorio en las siguientes carpetas :

* *jupyter* : aquí encontramos los códigos de los ataques de `Lagarias.ipynb` y `Coster.ipynb`, realizados en Sagemath. Estos programas incluyen en su cabecera una explicación de su funcionamiento y de su ejecución, según el resultado que queramos obtener. Incluso, se indican las variables que pueden ser modificadas para analizar diferentes resultados.

    Además, encontramos los archivos `MH_Grafica_Coster.py` y `MH_Lagarias_Coster.py`, necesarios para la ejecución de los anteriores. Sin embargo, estos archivos no deben ser modificados.

* *python* : en esta carpeta encontramos los archivos del criptosistema de Merkle-Hellman, tanto del método básico como del iterativo. Ambos están implementados en Python.

## Ejecución

Distinguimos la ejecución por carpetas :

* *jupyter* : para ejecutar estos programas, debemos abrirlos en un *notebook* de Jupyter y ejecutar cada celda para obtener sus resultados.

* *python* : para estos, simplemente debemos usar la orden de ejecución de Python :

    `python Merkle-Hellman_basico.py`

    `python Merkle-Hellman_iterativo.py`
