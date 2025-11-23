import hmac
import hashlib
import base64
from typing import Optional

class JWTVerifier:
    """Verificador criptográfico para firmas JWT"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode('utf-8')

    def verify_signature(self, header: str, payload: str, signature: str, algorithm: str) -> bool:
        """Verifica la firma de un JWT"""
        try:
            # Construir el mensaje a verificar
            message = f"{header}.{payload}".encode('utf-8')
            
            # Calcular la firma esperada
            expected_signature = self._calculate_signature(message, algorithm)
            
            # Comparar firmas (comparación segura contra timing attacks)
            return hmac.compare_digest(
                self._base64url_decode(signature),
                expected_signature
            )
        except Exception as e:
            print(f"Error en verificación: {e}")
            return False

    def _calculate_signature(self, message: bytes, algorithm: str) -> bytes:
        """Calcula la firma HMAC del mensaje"""
        if algorithm == 'HS256':
            hash_func = hashlib.sha256
        elif algorithm == 'HS384':
            hash_func = hashlib.sha384
        elif algorithm == 'HS512':
            hash_func = hashlib.sha512
        else:
            raise ValueError(f"Algoritmo no soportado: {algorithm}")
            
        return hmac.new(self.secret_key, message, hash_func).digest()

    def _base64url_decode(self, data: str) -> bytes:
        """Decodifica Base64URL a bytes"""
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding
        return base64.b64decode(data.replace('-', '+').replace('_', '/'))