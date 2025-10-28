#!/usr/bin/env python3

import argparse
import base64
import sys
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes



def parse_args():
    """
    Parser de argumentos de línea de comandos.
    """
    p = argparse.ArgumentParser(description="Cifra y luego descifra con DES, 3DES o AES-256 (CBC)")
    p.add_argument('--alg', choices=['DES', '3DES', 'AES'], required=True, help='Algoritmo')
    p.add_argument('--key', help='Clave (hex o texto).')
    p.add_argument('--iv', help='IV (hex o texto).')
    p.add_argument('--in', dest='in_text', help='Texto plano de entrada para cifrar.')
    return p.parse_args()


def to_bytes(s: str) -> bytes:
    """
    Convierte una cadena a bytes, intentando primero como hexadecimal.
    """
    try:
        return bytes.fromhex(s)
    except Exception:
        return s.encode()




def adjust_size_for_alg(alg: str, param_type: str, value: bytes) -> bytes:
    """
    Ajusta la longitud de la clave o IV según el algoritmo (DES, 3DES, AES-256).
    Si es menor al tamaño requerido, se completa con bytes aleatorios.
    Si es mayor, se trunca.
    """
    sizes = {
        'key': {'DES': 8, '3DES': 24, 'AES': 32},
        'iv':  {'DES': 8, '3DES': 8,  'AES': 16}
    }

    req = sizes[param_type][alg]

    if len(value) < req:
        value += get_random_bytes(req - len(value))
    elif len(value) > req:
        value = value[:req]
    return value



def encrypt(alg: str, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Cifra el texto plano usando el algoritmo especificado en modo CBC.
    Aplica padding PKCS7 al texto plano antes de cifrar.
    """
    if alg == 'DES':
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return cipher.encrypt(pad(plaintext, DES.block_size)) # se le aplica padding al texto plano al tamaño de bloque del algoritmo. El padding utilizado es PKCS7 por defecto.
    elif alg == '3DES':
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        return cipher.encrypt(pad(plaintext, DES3.block_size))
    elif alg == 'AES':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(plaintext, AES.block_size))
    else:
        raise ValueError('Unsupported algorithm')


def decrypt(alg: str, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Descifra el texto cifrado usando el algoritmo especificado en modo CBC.
    Remueve el padding PKCS7 después de descifrar.
    """
    if alg == 'DES':
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), DES.block_size)
    elif alg == '3DES':
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), DES3.block_size)
    elif alg == 'AES':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    else:
        raise ValueError('Unsupported algorithm')




def main():
    """
    Función principal que maneja la entrada del usuario, ajusta la clave y el IV,
    realiza el cifrado y descifrado, y muestra los resultados.
    """
    args = parse_args()

    # Obtener inputs (clave, iv, texto) faltantes 
    key_input = args.key
    if not key_input:
        key_input = input('Ingrese la key (hex o texto): ').strip()
    iv_input = args.iv
    if not iv_input:
        iv_input = input('Ingrese el IV (hex o texto): ').strip()
    in_text = args.in_text
    if not in_text:
        in_text = input('Ingrese el texto a cifrar: ').strip()

    # Texto plano o hexadecimal a bytes
    key = to_bytes(key_input) 
    iv = to_bytes(iv_input)

    print('\nClave sin ajustar (hex):', key.hex())
    print('IV sin ajustar (hex):', iv.hex())

    # Ajustar key e iv a los tamaños requeridos y luego se imprimen los valores
    key_adj = adjust_size_for_alg(args.alg, 'key', key)
    iv_adj = adjust_size_for_alg(args.alg, 'iv', iv)


    print('\nClave ajustada (hex):', key_adj.hex())
    print('IV ajustado (hex):', iv_adj.hex())


    plaintext = in_text.encode()

    # Cifrado y descifrado
    if args.alg == 'DES' or args.alg == '3DES' or args.alg == 'AES':
        ct = encrypt(args.alg, key_adj, iv_adj, plaintext)
        pt = decrypt(args.alg, key_adj, iv_adj, ct)
    else:
        print('Algoritmo no soportado', file=sys.stderr)
        sys.exit(2)

    ct_b64 = base64.b64encode(ct).decode()
    print('\nTexto cifrado (base64):', ct_b64)
    print('\nTexto descifrado:', pt.decode(errors='replace'))


if __name__ == '__main__':
    main()
