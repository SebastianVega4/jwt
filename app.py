from flask import Flask, request, jsonify
from flask_cors import CORS
from model.parser import JWTParser
from model.lexer import JWTlexer
from model.semantic import JWTSemanticAnalyzer
from model.automata import JWTStructureDFA
from model.crypto import JWTVerifier
from model.utils import show_tree
from model.db import init_db, save_result, get_history


app = Flask(__name__)
CORS(app)  # Permite peticiones desde el frontend (localhost:3000)

# -------- Análisis y validación de JWT --------
@app.route('/api/analyze', methods=['POST'])
def analyze_jwt():
    data = request.get_json()
    jwt_string = data.get('jwt')
    secret = data.get('secret', '')  # opcional para firma

    result = {}
    try:
        # 1. DFA estructura JWT
        dfa = JWTStructureDFA()
        result['estructura_valida'] = dfa.process(jwt_string)

        # 2. Parsing y decodificación de header/payload
        lexer = JWTlexer()
        parser = JWTParser(lexer)

        components = parser.parse(jwt_string)
        header = parser.decode_base64url(components['HEADER'])
        payload = parser.decode_base64url(components['PAYLOAD'])
        result['header'] = header
        result['payload'] = payload

        # 3. Árbol (opcional, solo si show_tree imprime, si tienes)
        import io, sys
        output = io.StringIO()
        sys.stdout = output
        show_tree(jwt_string)
        sys.stdout = sys.__stdout__
        result['arbol_derivacion'] = output.getvalue()

        # 4. Validación semántica
        semantic = JWTSemanticAnalyzer()
        semantic.analyze(header, payload)
        result['errores'] = semantic.errors
        result['warnings'] = semantic.warnings

        # 5. Firma según algoritmo
        alg = header.get('alg', 'HS256') if isinstance(header, dict) else 'HS256'
        if secret and alg in ["HS256", "HS384"]:
            result['firma_valida'] = JWTVerifier.verify_signature(jwt_string, secret, alg)
        elif secret and alg not in ["HS256", "HS384"]:
            result['firma_valida'] = f"Algoritmo '{alg}' no soportado para verificación local"
        else:
            result['firma_valida'] = "Sin clave para verificar"

        save_result(jwt_string, result)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# -------- Generación de JWT desde objetos JSON --------
@app.route('/api/generate', methods=['POST'])
def generate_jwt_api():
    data = request.get_json()
    header = data.get('header')
    payload = data.get('payload')
    secret = data.get('secret', '')
    algorithm = data.get('algorithm', 'HS256')
    try:
        import jwt
        token = jwt.encode(payload, secret, algorithm=algorithm, headers=header)
        return jsonify({'jwt': token})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# -------- Historial de análisis de JWT --------
@app.route('/api/history', methods=['GET'])
def get_analysis_history():
    history = get_history()
    return jsonify(history)

if __name__ == "__main__":
    init_db()
    app.run(host='0.0.0.0', port=5000)
