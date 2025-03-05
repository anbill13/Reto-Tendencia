from fastapi import FastAPI
from pydantic import BaseModel
import base64
import time
import threading
import random
from datetime import datetime  # Importar para obtener la hora actual
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer

# Crear la aplicación FastAPI
app = FastAPI()

# Variable global para cancelar la ejecución
delete_attack = threading.Event()

# Clave AES-256 de 32 bytes (256 bits)
AES_KEY = get_random_bytes(32)

# Modelo de datos para recibir la clave cifrada
class CiphertextInput(BaseModel):
    ciphertext: str  # Clave cifrada en Base64
    iv: str  # Vector de Inicialización en Base64

# Función para cifrar una clave con AES-256 (CBC)
def encrypt_key():
    key = ''.join(random.choice('01') for _ in range(128))  # Clave binaria de 128 bits
    key_bytes = key.encode()  # Convertir a bytes
    iv = get_random_bytes(16)  # Generar IV de 16 bytes
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    
    # Relleno PKCS7
    pad_length = 16 - (len(key_bytes) % 16)
    padded_key = key_bytes + bytes([pad_length] * pad_length)
    
    encrypted_key = cipher.encrypt(padded_key)  # Cifrar la clave
    return base64.b64encode(encrypted_key).decode(), base64.b64encode(iv).decode()

# Función para descifrar la clave con AES-256 (CBC)
def decrypt_key(ciphertext, iv):
    encrypted_key_bytes = base64.b64decode(ciphertext)
    iv_bytes = base64.b64decode(iv)
    
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv_bytes)
    decrypted_padded_key = cipher.decrypt(encrypted_key_bytes)
    
    # Eliminar el padding PKCS7
    pad_length = decrypted_padded_key[-1]
    decrypted_key = decrypted_padded_key[:-pad_length]
    
    return decrypted_key.decode()

# Función para convertir la clave descifrada a binario y usar los 128 bits completos
def binary_key_truncate(key):
    binary_key = ''.join(format(byte, '08b') for byte in key.encode())  # Convertir clave descifrada a binario
    return binary_key[:128]  # Tomar los 128 bits completos

# Algoritmo de Grover: Oráculo Cuántico
def oracle(qc, key, n_bits):
    for i, bit in enumerate(key):
        if bit == '0':
            qc.x(i)
    qc.mcx(list(range(n_bits)), n_bits)  # Multi-Controlled X (MCX)
    for i, bit in enumerate(key):
        if bit == '0':
            qc.x(i)

# Algoritmo de Grover: Difusor
def diffuser(qc, n_bits):
    """
    Difusor en el algoritmo de Grover:
    - Aplica Hadamard para transformar las amplitudes cuánticas.
    - Realiza una inversión sobre la media para amplificar el estado correcto.
    - Usa Multi-Controlled X (MCX) para reflejar las amplitudes en torno a la media.
    """
    qc.h(range(n_bits))
    qc.x(range(n_bits))
    qc.h(n_bits - 1)
    qc.mcx(list(range(n_bits - 1)), n_bits - 1)
    qc.h(n_bits - 1)
    qc.x(range(n_bits))
    qc.h(range(n_bits))

# Implementación del Algoritmo de Grover (Ahora con 128 bits)
def grovers_algorithm(secret_key, n_bits=128):
    """
    Implementación del algoritmo de Grover:
    - Se inicializa el circuito con una superposición uniforme.
    - Se calcula el número óptimo de iteraciones para amplificar la probabilidad del estado correcto.
    - Se aplican el oráculo y el difusor en cada iteración.
    - Se muestra la hora exacta del inicio y el número de intentos.
    """
    qc = QuantumCircuit(n_bits + 1, n_bits)
    qc.h(range(n_bits))
    qc.x(n_bits)
    qc.h(n_bits)

    # Obtener la hora exacta del inicio del ataque
    start_time = datetime.now().strftime("%H:%M:%S")  # Formato HH:MM:SS
    print(f"Inicio del ataque a las {start_time}")

    # Cálculo óptimo del número de iteraciones basado en Grover
    iterations = int((3.14 / 4) * (2**(n_bits / 2)))  

    print("Ejecutando ataque...")  # Mensaje inicial único

    attempts = 0  # Contador de intentos

    for i in range(iterations):
        if delete_attack.is_set():  
            print(f"Proceso interrumpido. Se realizaron {attempts} intentos.")
            return None  
        
        attempts += 1  # Incrementar el contador
        print(f"Ejecutando ataque... Intentos: {attempts}")  # Mostrar intentos en la terminal
        time.sleep(0.22)  # Mantiene el tiempo de ejecución realista

        oracle(qc, secret_key, n_bits)
        diffuser(qc, n_bits)

    print(f"Ataque completado. Total de intentos: {attempts}")
    
    qc.measure(range(n_bits), range(n_bits))
    return qc

# Endpoint para generar una clave cifrada con AES-256
@app.get("/cifrado")
def cifrado():
    ciphertext, iv = encrypt_key()
    return {"ciphertext": ciphertext, "iv": iv}

# Endpoint para ejecutar el ataque cuántico
@app.post("/ataque")
def ataque(data: CiphertextInput):
    global delete_attack
    delete_attack.clear()  

    ciphertext = data.ciphertext
    iv = data.iv

    start_time = time.time()

    # Descifrar la clave AES
    decrypted_key = decrypt_key(ciphertext, iv)

    # Extraer los 128 bits completos en binario
    secret_key = binary_key_truncate(decrypted_key)
    n_bits = len(secret_key)  # Ahora será 128 en lugar de 35

    # Ejecutar Grover con los 128 bits
    qc = grovers_algorithm(secret_key, n_bits)
    if qc is None:
        return {"message": "Ataque cancelado por el usuario."}

    backend = Aer.get_backend('qasm_simulator')  

    tq = transpile(qc, backend)
    job = backend.run(tq, shots=1024)
    result = job.result()
    counts = result.get_counts()

    end_time = time.time()
    elapsed_time = end_time - start_time

    return {
        "ciphertext": ciphertext,
        "binary_key": secret_key,
        "attack_results": counts,
        "execution_time": f"{elapsed_time // 60:.0f} minutos y {elapsed_time % 60:.2f} segundos"
    }

# Endpoint para cancelar el ataque cuántico
@app.get("/cancel")
def cancel():
    delete_attack.set()
    return {"message": "El ataque cuántico ha sido cancelado."}


# Ejecutar con: uvicorn RetoTendencia:app --reload
