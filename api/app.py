from flask import Flask, request, jsonify
from flask_cors import CORS
from model.parser import JWTParser
from model.lexer import JWTlexer
from model.semantic import JWTSemanticAnalyzer
from model.automata import JWTStructureDFA
from model.crypto import JWTVerifier
from model.utils import show_tree
from model.db import init_db, save_result, get_history, delete_history_record # Import delete_history_record
import jwt  # Asegurar que se importa
import os
from bson.errors import InvalidId # Import InvalidId

app = Flask(__name__)
CORS(app)

# Configuración para producción
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb+srv://johanvega01_db_user:CmMw8mO4ow2ehjh5@cluster0.pyavozq.mongodb.net/?appName=Cluster0')

@app.route('/api/analyze', methods=['POST'])
def analyze_jwt():
    data = request.get_json()
    jwt_string = data.get('jwt', '')
    secret = data.get('secret', '')

    if not jwt_string:
        return jsonify({'error': 'No se proporcionó JWT'}), 400

    result = {}
    try:
        # 1. DFA estructura JWT
        dfa = JWTStructureDFA()
        result['estructura_valida'] = dfa.process(jwt_string)

        # 2. Parsing y decodificación
        lexer = JWTlexer()
        parser = JWTParser(lexer)
        components = parser.parse(jwt_string)
        header = parser.decode_base64url(components['HEADER'])
        payload = parser.decode_base64url(components['PAYLOAD'])
        result['header'] = header
        result['payload'] = payload

        # 3. Árbol de derivación
        import io, sys
        output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = output
        show_tree(jwt_string)
        sys.stdout = old_stdout
        result['arbol_derivacion'] = output.getvalue()

        # 4. Validación semántica
        semantic = JWTSemanticAnalyzer()
        semantic.analyze(header, payload)
        result['errores'] = semantic.errors
        result['warnings'] = semantic.warnings

        # 5. Verificación de firma
        alg = header.get('alg', 'HS256') if isinstance(header, dict) else 'HS256'
        if secret and alg in ["HS256", "HS384"]:
            result['firma_valida'] = JWTVerifier.verify_signature(jwt_string, secret, alg)
        elif secret and alg not in ["HS256", "HS384"]:
            result['firma_valida'] = f"Algoritmo '{alg}' no soportado"
        else:
            result['firma_valida'] = "Sin clave para verificar"

        # Guardar en base de datos
        save_result(jwt_string, result)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/generate', methods=['POST'])
def generate_jwt_api():
    data = request.get_json()
    header = data.get('header', {})
    payload = data.get('payload', {})
    secret = data.get('secret', '')
    algorithm = data.get('algorithm', 'HS256')

    if not header or not payload:
        return jsonify({'error': 'Header y payload son requeridos'}), 400

    try:
        # Usar PyJWT para generar el token
        token = jwt.encode(
            payload, 
            secret, 
            algorithm=algorithm, 
            headers=header
        )
        return jsonify({'jwt': token})
    except Exception as e:
        return jsonify({'error': f'Error generando JWT: {str(e)}'}), 400

@app.route('/api/history', methods=['GET'])
def get_analysis_history():
    try:
        history = get_history()
        return jsonify(history)
    except Exception as e:
        return jsonify({'error': f'Error obteniendo historial: {str(e)}'}), 500

@app.route('/api/history/<record_id>', methods=['DELETE'])
def delete_analysis_history(record_id):
    try:
        if delete_history_record(record_id):
            return jsonify({'message': 'Registro de historial eliminado correctamente'}), 200
        else:
            return jsonify({'error': 'Registro de historial no encontrado o no se pudo eliminar'}), 404
    except InvalidId:
        return jsonify({'error': 'ID de registro inválido'}), 400
    except Exception as e:
        return jsonify({'error': f'Error al eliminar registro de historial: {str(e)}'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy', 
        'database': 'connected' if init_db() else 'disconnected'
    })

if __name__ == "__main__":
    init_db()
    app.run(host='0.0.0.0', port=5000)