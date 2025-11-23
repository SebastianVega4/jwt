import base64
import json
from typing import Dict, Any

class Base64URLDecoder:
    """Decodificador especializado para Base64URL"""
    
    @staticmethod
    def decode(encoded_str: str) -> bytes:
        """Decodifica una cadena Base64URL a bytes"""
        # Agregar padding si es necesario
        padding = 4 - (len(encoded_str) % 4)
        if padding != 4:
            encoded_str += '=' * padding
            
        # Convertir de Base64URL a Base64 estándar
        standard_base64 = encoded_str.replace('-', '+').replace('_', '/')
        
        # Decodificar
        return base64.b64decode(standard_base64)

    @staticmethod
    def decode_to_json(encoded_str: str) -> Dict[str, Any]:
        """Decodifica Base64URL a objeto JSON"""
        try:
            decoded_bytes = Base64URLDecoder.decode(encoded_str)
            decoded_str = decoded_bytes.decode('utf-8')
            return json.loads(decoded_str)
        except Exception as e:
            raise ValueError(f"Error decodificando JSON: {str(e)}")

class Base64URLEncoder:
    """Codificador especializado para Base64URL"""
    
    @staticmethod
    def encode(data: bytes) -> str:
        """Codifica bytes a Base64URL"""
        encoded = base64.b64encode(data).decode('utf-8')
        # Convertir de Base64 estándar a Base64URL
        encoded = encoded.replace('+', '-').replace('/', '_').replace('=', '')
        return encoded

    @staticmethod
    def encode_from_json(json_obj: Dict[str, Any]) -> str:
        """Codifica objeto JSON a Base64URL"""
        json_str = json.dumps(json_obj, separators=(',', ':'))
        return Base64URLEncoder.encode(json_str.encode('utf-8'))