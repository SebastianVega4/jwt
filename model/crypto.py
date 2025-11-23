import hmac
import hashlib
import base64

class JWTVerifier:
    @staticmethod
    def verify_signature(jwt_string: str, secret: str, algorithm: str) -> bool:
        try:
            parts = jwt_string.split('.')
            if len(parts) != 3:
                return False
            message = f"{parts[0]}.{parts[1]}".encode('utf-8')
            secret_key = secret.encode('utf-8')
            if algorithm == 'HS256':
                hash_func = hashlib.sha256
            elif algorithm == 'HS384':
                hash_func = hashlib.sha384
            elif algorithm == 'HS512':
                hash_func = hashlib.sha512
            else:
                return False
            expected_sig = hmac.new(secret_key, message, hash_func).digest()
            # Decodificar firma en Base64URL
            sig = JWTVerifier._base64url_decode_to_bytes(parts[2])
            return hmac.compare_digest(sig, expected_sig)
        except Exception as e:
            return False

    @staticmethod
    def _base64url_decode_to_bytes(data: str) -> bytes:
        padding = '=' * ((4 - len(data) % 4) % 4)
        return base64.urlsafe_b64decode(data + padding)
