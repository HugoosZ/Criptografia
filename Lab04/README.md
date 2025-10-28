# Crypto CLI

Script en Python para cifrar/descifrar texto usando DES, 3DES y AES-256 en modo CBC.

Instalación:

```bash
python3 -m pip install -r requirements.txt
```

Ejemplo:


```bash
python3 encryption_cbc.py dec --alg <algoritmo> --key <key> --iv <iv> --in <text>
```

Notas:

- La key y el IV se rellenan con digitos aleatorios si no se cumple el tamaño de ambos parametros, si se sobrepasa el tamaño se truncan.
- El script acepta la key y el iv en hex (si el string es hex válido) o como texto puro.
- Se usa PKCS#7 padding (Crypto.Util.Padding.pad/unpad).

