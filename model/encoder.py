import base64
import json

class JWTEncoder:
    @staticmethod
    def encode_json_to_base64url(data: dict) -> str:
        json_str = json.dumps(data, separators=(',', ':'))
        base64url = base64.urlsafe_b64encode(json_str.encode()).decode().rstrip('=')
        return base64url

    @staticmethod
    def decode_base64url_to_json(base64url_string: str) -> dict:
        padding = '=' * ((4 - len(base64url_string) % 4) % 4)
        try:
            decoded = base64.urlsafe_b64decode(base64url_string + padding).decode()
            return json.loads(decoded)
        except Exception as e:
            return {"error": f"Base64URL/JSON inválido ({str(e)})"}
