import requests
import random
from collections import Counter

# URL donde se encuentran los datos históricos
url = "https://www.pronostigol.es/api/bonoloto/historical/occurrencesByNumber"


def obtener_datos(url):
    """Descargar los datos históricos desde la URL proporcionada"""
    respuesta = requests.get(url)
    if respuesta.status_code == 200:
        return respuesta.json()
    else:
        raise Exception(f"Error al obtener datos: {respuesta.status_code}")


def numero_mas_probable(datos, cantidad_numeros=5):
    """Devuelve los números más probables basados en la frecuencia"""
    frecuencia = Counter()

    # Contar la frecuencia de aparición de los números
    for numero, ocurrencias in datos.items():
        frecuencia[int(numero)] = ocurrencias

    # Obtener los números más comunes
    numeros_mas_frecuentes = [num for num, _ in frecuencia.most_common(cantidad_numeros)]
    return numeros_mas_frecuentes


def resultado_azar(cantidad_numeros=5, rango_numeros=49):
    """Devuelve un conjunto de números aleatorios"""
    return random.sample(range(1, rango_numeros + 1), cantidad_numeros)


# Descargar los datos históricos
datos_historicos = obtener_datos(url)

# Generar el resultado más probable
resultado_probable = numero_mas_probable(datos_historicos)

# Generar el resultado aleatorio
resultado_aleatorio = resultado_azar()

# Mostrar los resultados
print(f"Resultado más probable: {resultado_probable}")
print(f"Resultado al azar: {resultado_aleatorio}")
