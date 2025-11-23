from .encoder import JWTEncoder

class JWTParser:
    def __init__(self, lexer):
        self.lexer = lexer

    def parse(self, jwt_string: str):
        tokens = self.lexer.tokenize(jwt_string)
        return {
            'HEADER': tokens[0][1],
            'PAYLOAD': tokens[2][1],
            'SIGNATURE': tokens[4][1]
        }

    def decode_base64url(self, base64url_string: str):
        return JWTEncoder.decode_base64url_to_json(base64url_string)
