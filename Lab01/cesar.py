import sys

def cifrado_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():  # Si es letra
            # Trabajamos en minúsculas
            base = ord('a') if caracter.islower() else ord('A')
            # Aplicamos el desplazamiento con módulo 26
            resultado += chr((ord(caracter) - base + desplazamiento) % 26 + base)
        else:
            # Mantiene espacios y otros símbolos
            resultado += caracter
    return resultado

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py \"texto a cifrar\" desplazamiento")
        sys.exit(1)
    
    texto = sys.argv[1]
    desplazamiento = int(sys.argv[2])
    
    cifrado = cifrado_cesar(texto, desplazamiento)
    print(cifrado)