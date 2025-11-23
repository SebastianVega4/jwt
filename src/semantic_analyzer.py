import time
from typing import Dict, List, Tuple, Any, Union

class JWTSemanticAnalyzer:
    """Analizador semántico para validación de JWT"""
    
    def __init__(self):
        self.symbol_table = {}
        self.errors = []
        self.warnings = []
        
        # Algoritmos soportados
        self.valid_algorithms = {
            'HS256', 'HS384', 'HS512',  # HMAC
            'RS256', 'RS384', 'RS512',  # RSA
            'ES256', 'ES384', 'ES512',  # ECDSA
            'none'  # Para casos especiales (con validación estricta)
        }
        
        # Claims estándar registrados
        self.registered_claims = {
            'iss': str,                    # Issuer
            'sub': str,                    # Subject
            'aud': (str, list),           # Audience
            'exp': (int, float),          # Expiration
            'nbf': (int, float),          # Not Before
            'iat': (int, float),          # Issued At
            'jti': str                    # JWT ID
        }

    def analyze(self, syntax_tree: Dict[str, Any]) -> Dict[str, Any]:
        """Realiza análisis semántico completo del JWT"""
        self.errors.clear()
        self.warnings.clear()
        self.symbol_table.clear()
        
        try:
            # Extraer componentes del árbol sintáctico
            header_data = self._extract_component_data(syntax_tree, 'HEADER')
            payload_data = self._extract_component_data(syntax_tree, 'PAYLOAD')
            
            # Validar header
            self._validate_header(header_data)
            
            # Validar payload
            self._validate_payload(payload_data)
            
            # Validar claims temporales
            self._validate_temporal_claims(payload_data)
            
            # Construir tabla de símbolos
            self._build_symbol_table(header_data, payload_data)
            
            return {
                'valid': len(self.errors) == 0,
                'errors': self.errors,
                'warnings': self.warnings,
                'symbol_table': self.symbol_table
            }
            
        except Exception as e:
            self.errors.append(f"Error interno del analizador: {str(e)}")
            return {
                'valid': False,
                'errors': self.errors,
                'warnings': self.warnings,
                'symbol_table': self.symbol_table
            }

    def _validate_header(self, header: Dict[str, Any]) -> None:
        """Valida semánticamente el header del JWT"""
        if 'error' in header:
            self.errors.append("Header no decodificable")
            return
            
        # Validar campo 'alg' obligatorio
        if 'alg' not in header:
            self.errors.append("Header debe contener el campo 'alg'")
        elif header['alg'] not in self.valid_algorithms:
            self.errors.append(f"Algoritmo '{header['alg']}' no válido")
        elif header['alg'] == 'none':
            self.warnings.append("Algoritmo 'none' detectado - posible vulnerabilidad")
            
        # Validar campo 'typ' obligatorio
        if 'typ' not in header:
            self.errors.append("Header debe contener el campo 'typ'")
        elif header['typ'] != 'JWT':
            self.errors.append(f"Campo 'typ' debe ser 'JWT', encontrado: '{header['typ']}'")

    def _validate_payload(self, payload: Dict[str, Any]) -> None:
        """Valida semánticamente el payload del JWT"""
        if 'error' in payload:
            self.errors.append("Payload no decodificable")
            return
            
        # Validar tipos de claims registrados
        for claim, value in payload.items():
            if claim in self.registered_claims:
                expected_types = self.registered_claims[claim]
                if not isinstance(expected_types, tuple):
                    expected_types = (expected_types,)
                    
                if not isinstance(value, expected_types):
                    type_names = [t.__name__ for t in expected_types]
                    self.errors.append(
                        f"Claim '{claim}' debe ser de tipo {' o '.join(type_names)}, "
                        f"encontrado: {type(value).__name__}"
                    )

    def _validate_temporal_claims(self, payload: Dict[str, Any]) -> None:
        """Valida claims temporales del payload"""
        if 'error' in payload:
            return
            
        current_time = time.time()
        
        # Validar expiración (exp)
        if 'exp' in payload:
            if isinstance(payload['exp'], (int, float)):
                if payload['exp'] < current_time:
                    self.errors.append("Token ha expirado")
            else:
                self.errors.append("Claim 'exp' debe ser un timestamp numérico")
                
        # Validar not before (nbf)
        if 'nbf' in payload:
            if isinstance(payload['nbf'], (int, float)):
                if payload['nbf'] > current_time:
                    self.errors.append("Token aún no es válido (nbf)")
            else:
                self.errors.append("Claim 'nbf' debe ser un timestamp numérico")
                
        # Validar issued at (iat)
        if 'iat' in payload:
            if isinstance(payload['iat'], (int, float)):
                if payload['iat'] > current_time + 300:  # Tolerancia de 5 minutos
                    self.warnings.append("Token emitido en el futuro")
            else:
                self.errors.append("Claim 'iat' debe ser un timestamp numérico")

    def _build_symbol_table(self, header: Dict[str, Any], payload: Dict[str, Any]) -> None:
        """Construye la tabla de símbolos"""
        if 'error' not in header:
            for key, value in header.items():
                self.symbol_table[f"header.{key}"] = {
                    'type': type(value).__name__,
                    'value': value,
                    'scope': 'header'
                }
                
        if 'error' not in payload:
            for key, value in payload.items():
                self.symbol_table[f"payload.{key}"] = {
                    'type': type(value).__name__,
                    'value': value,
                    'scope': 'payload'
                }

    def _extract_component_data(self, syntax_tree: Dict[str, Any], component_type: str) -> Dict[str, Any]:
        """Extrae datos decodificados de un componente específico"""
        for child in syntax_tree.get('children', []):
            if child['type'] == component_type:
                return child.get('decoded', {'error': 'No decodificado'})
        return {'error': f'Componente {component_type} no encontrado'}