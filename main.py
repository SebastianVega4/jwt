from model.parser import JWTParser
from model.semantic import JWTSemanticAnalyzer
from model.automata import JWTStructureDFA
from model.utils import show_tree
from tests import test_cases
from model.lexer import JWTlexer

def run(jwt_string, label=""):
    try:
        lexer = JWTlexer()
        parser = JWTParser(lexer)
        semantic = JWTSemanticAnalyzer()
        dfa = JWTStructureDFA()
        print(f"{label}Estructura válida?:", dfa.process(jwt_string))
        components = parser.parse(jwt_string)
        header = parser.decode_base64url(components['HEADER'])
        payload = parser.decode_base64url(components['PAYLOAD'])
        print("Header:", header)
        print("Payload:", payload)
        show_tree(jwt_string)
        semantic.analyze(header, payload)
        print("Errores:", semantic.errors)
        print("Warnings:", semantic.warnings)
    except Exception as e:
        print(f"{label}Error detectado:", str(e))

if __name__ == "__main__":
    run(test_cases.JWT_VALID, "\nPrueba JWT válido:\n")
    run(test_cases.JWT_MALFORMED, "\nPrueba JWT malformado:\n")
    run(test_cases.JWT_EXPIRED, "\nPrueba JWT expirado:\n")
