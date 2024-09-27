import requests
import random
import csv
from collections import Counter
from io import StringIO  # Para convertir bytes a string IO

# URL donde se encuentran los datos históricos
url = "https://docs.google.com/spreadsheets/d/e/2PACX-1vRy91wfK2JteoMi1ZOhGm0D1RKJfDTbEOj6rfnrB6-X7n2Q1nfFwBZBpcivHRdg3pSwxSQgLA3KpW7v/pub?output=csv"


def obtener_datos(url):
    """Descargar los datos históricos desde la URL proporcionada"""
    respuesta = requests.get(url, timeout=10, verify=False)
    if respuesta.status_code == 200:
        # Decodificar el contenido a una cadena
        contenido = respuesta.content.decode('utf-8')

        # Convertir la cadena a un formato CSV legible
        csv_data = csv.reader(StringIO(contenido))

        # Convertir el CSV a una lista de listas
        datos = list(csv_data)
        return datos
    else:
        raise Exception(f"Error al obtener datos: {respuesta.status_code}")


def numero_mas_probable(datos, cantidad_numeros=5):
    """Devuelve los números más probables basados en la frecuencia"""
    frecuencia = Counter()

    # Contar la frecuencia de aparición de los números principales (índices 1 a 5)
    for fila in datos[1:]:  # Saltar el encabezado
        numeros = fila[1:6]  # Números principales
        for numero in numeros:
            if numero.isdigit():  # Asegurarse de contar solo números
                frecuencia[int(numero)] += 1

    # Obtener los números más comunes
    numeros_mas_frecuentes = [num for num, _ in frecuencia.most_common(cantidad_numeros)]
    return numeros_mas_frecuentes


def estrellas_mas_probables(datos, cantidad_estrellas=2):
    """Devuelve las estrellas más probables basadas en la frecuencia"""
    frecuencia_estrellas = Counter()

    # Contar la frecuencia de aparición de las estrellas (índices 7 y 8)
    for fila in datos[1:]:  # Saltar el encabezado
        estrellas = fila[7:9]  # Estrellas
        for estrella in estrellas:
            if estrella.isdigit():  # Asegurarse de contar solo números
                frecuencia_estrellas[int(estrella)] += 1

    # Obtener las estrellas más comunes
    estrellas_mas_frecuentes = [num for num, _ in frecuencia_estrellas.most_common(cantidad_estrellas)]
    return estrellas_mas_frecuentes


def resultado_azar(cantidad_numeros=5, rango_numeros=49):
    """Devuelve un conjunto de números aleatorios"""
    return random.sample(range(1, rango_numeros + 1), cantidad_numeros)


def estrellas_azar(cantidad_estrellas=2, rango_estrellas=12):
    """Devuelve un conjunto de estrellas aleatorias"""
    return random.sample(range(1, rango_estrellas + 1), cantidad_estrellas)


# Descargar los datos históricos
datos_historicos = obtener_datos(url)

# Generar el resultado más probable para números
resultado_probable_numeros = numero_mas_probable(datos_historicos)

# Generar el resultado más probable para estrellas
resultado_probable_estrellas = estrellas_mas_probables(datos_historicos)

# Generar un resultado aleatorio de números
resultado_aleatorio_numeros = resultado_azar()

# Generar un resultado aleatorio de estrellas
resultado_aleatorio_estrellas = estrellas_azar()

# Mostrar los resultados
print(f"Resultado más probable (Números): {resultado_probable_numeros}")
print(f"Resultado más probable (Estrellas): {resultado_probable_estrellas}")
print(f"Resultado al azar (Números): {resultado_aleatorio_numeros}")
print(f"Resultado al azar (Estrellas): {resultado_aleatorio_estrellas}")
