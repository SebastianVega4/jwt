import re
import base64
import json
from typing import List, Tuple, Optional, Dict, Any

class JWTlexer:
    """Analizador léxico para tokens JWT"""
    
    def __init__(self):
        self.tokens = []
        self.position = 0
        self.current_token = None
        
        # Definición de tokens
        self.token_patterns = [
            ('HEADER', r'[A-Za-z0-9_-]+'),
            ('PAYLOAD', r'[A-Za-z0-9_-]+'),
            ('SIGNATURE', r'[A-Za-z0-9_-]*'),
            ('SEPARATOR', r'\.'),
            ('JSON_FIELD', r'"[\w]+"'),
            ('JSON_VALUE', r'".*?"|\d+|true|false|null'),
        ]

    def tokenize(self, jwt_string: str) -> List[Tuple[str, str]]:
        """Tokeniza una cadena JWT completa"""
        if not isinstance(jwt_string, str):
            raise TypeError("El input debe ser una cadena")
            
        # Validar estructura básica
        parts = jwt_string.split('.')
        if len(parts) != 3:
            raise ValueError("JWT malformado: debe contener exactamente 3 partes")
            
        # Validar cada componente
        for i, part in enumerate(parts):
            component_name = ['HEADER', 'PAYLOAD', 'SIGNATURE'][i]
            if not self._is_valid_base64url(part):
                raise ValueError(f"{component_name} no es Base64URL válida")
                
        # Generar tokens
        self.tokens = [
            ('HEADER', parts[0]),
            ('SEPARATOR', '.'),
            ('PAYLOAD', parts[1]),
            ('SEPARATOR', '.'),
            ('SIGNATURE', parts[2])
        ]
        
        self.position = 0
        return self.tokens

    def _is_valid_base64url(self, s: str) -> bool:
        """Valida si una cadena es Base64URL válida"""
        if not s:
            return False
            
        pattern = r'^[A-Za-z0-9_-]*$'
        return bool(re.match(pattern, s))

    def get_next_token(self) -> Optional[Tuple[str, str]]:
        """Obtiene el siguiente token"""
        if self.position < len(self.tokens):
            token = self.tokens[self.position]
            self.position += 1
            self.current_token = token
            return token
        return None

    def reset(self):
        """Reinicia el estado del lexer"""
        self.position = 0
        self.current_token = None

    def get_all_tokens(self) -> List[Tuple[str, str]]:
        """Retorna todos los tokens"""
        return self.tokens.copy()