import base64
import json
from typing import Dict, Any, Optional
from .lexer import JWTlexer
from .base64url import Base64URLDecoder

class JWTParser:
    """Parser sintáctico descendente recursivo para JWT"""
    
    def __init__(self, lexer: JWTlexer):
        self.lexer = lexer
        self.current_token = None
        self.syntax_tree = None
        self.decoder = Base64URLDecoder()

    def parse(self, jwt_string: str) -> Dict[str, Any]:
        """Analiza sintácticamente un JWT"""
        try:
            # Tokenización
            self.lexer.tokenize(jwt_string)
            self.lexer.reset()
            self.current_token = self.lexer.get_next_token()
            
            # Análisis sintáctico
            jwt_node = self._parse_jwt()
            
            return {
                'valid': True,
                'syntax_tree': jwt_node,
                'message': 'JWT sintácticamente válido'
            }
            
        except Exception as e:
            return {
                'valid': False,
                'syntax_tree': None,
                'message': f'Error sintáctico: {str(e)}'
            }

    def _parse_jwt(self) -> Dict[str, Any]:
        """Parsea la producción JWT → HEADER . PAYLOAD . SIGNATURE"""
        jwt_node = {
            'type': 'JWT',
            'children': []
        }

        # Parsear HEADER
        if not self.current_token or self.current_token[0] != 'HEADER':
            raise SyntaxError("Se esperaba HEADER")

        header_node = {
            'type': 'HEADER',
            'value': self.current_token[1],
            'decoded': self._decode_base64url(self.current_token[1])
        }
        jwt_node['children'].append(header_node)
        self.current_token = self.lexer.get_next_token()

        # Parsear primer separador
        if not self.current_token or self.current_token[0] != 'SEPARATOR':
            raise SyntaxError("Se esperaba separador '.'")
        self.current_token = self.lexer.get_next_token()

        # Parsear PAYLOAD
        if not self.current_token or self.current_token[0] != 'PAYLOAD':
            raise SyntaxError("Se esperaba PAYLOAD")

        payload_node = {
            'type': 'PAYLOAD',
            'value': self.current_token[1],
            'decoded': self._decode_base64url(self.current_token[1])
        }
        jwt_node['children'].append(payload_node)
        self.current_token = self.lexer.get_next_token()

        # Parsear segundo separador
        if not self.current_token or self.current_token[0] != 'SEPARATOR':
            raise SyntaxError("Se esperaba separador '.'")
        self.current_token = self.lexer.get_next_token()

        # Parsear SIGNATURE
        if not self.current_token or self.current_token[0] != 'SIGNATURE':
            raise SyntaxError("Se esperaba SIGNATURE")

        signature_node = {
            'type': 'SIGNATURE',
            'value': self.current_token[1]
        }
        jwt_node['children'].append(signature_node)

        return jwt_node

    def _decode_base64url(self, encoded_str: str) -> Dict[str, Any]:
        """Decodifica una cadena Base64URL a JSON"""
        try:
            decoded_data = self.decoder.decode_to_json(encoded_str)
            return decoded_data
        except Exception as e:
            return {'error': f'Error de decodificación: {str(e)}'}

    def extract_component_data(self, syntax_tree: Dict[str, Any], component_type: str) -> Dict[str, Any]:
        """Extrae datos decodificados de un componente específico"""
        for child in syntax_tree.get('children', []):
            if child['type'] == component_type:
                return child.get('decoded', {'error': 'No decodificado'})
        return {'error': f'Componente {component_type} no encontrado'}