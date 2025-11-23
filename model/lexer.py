from .automata import Base64URLDFA

class JWTlexer:
    def tokenize(self, jwt_string: str):
        parts = jwt_string.split('.')
        if len(parts) != 3:
            raise ValueError("JWT malformado: no tiene 3 partes")
        dfa = Base64URLDFA()
        for i, part in enumerate(parts):
            if not dfa.process(part):
                raise ValueError(f"Parte {i+1} no es Base64URL válida por autómata")
        return [
            ('HEADER', parts[0]),
            ('SEPARATOR', '.'),
            ('PAYLOAD', parts[1]),
            ('SEPARATOR', '.'),
            ('SIGNATURE', parts[2])
        ]
