from flask import Flask, request, jsonify
from flask_cors import CORS
import pymongo
from datetime import datetime
import json
import sys
import os

# Agregar el directorio src al path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from lexer import JWTlexer
from parser import JWTParser
from semantic_analyzer import JWTSemanticAnalyzer
from advanced_verifier import AdvancedJWTVerifier

app = Flask(__name__)
CORS(app)

# Configuración de MongoDB (usar variable de entorno en producción)
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
client = pymongo.MongoClient(MONGODB_URI)
db = client.jwt_analyzer
test_cases_collection = db.test_cases

@app.route('/api/analyze', methods=['POST'])
def analyze_jwt():
    """Endpoint principal para análisis de JWT"""
    try:
        data = request.get_json()
        jwt_token = data.get('token', '')
        secret = data.get('secret', '')
        
        # Inicializar analizador completo
        lexer = JWTlexer()
        parser = JWTParser(lexer)
        semantic_analyzer = JWTSemanticAnalyzer()
        verifier = AdvancedJWTVerifier()
        
        # Realizar análisis completo
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'input_token': jwt_token
        }
        
        # Análisis léxico
        try:
            lexer.tokenize(jwt_token)
            result['lexical'] = {
                'valid': True, 
                'tokens': lexer.get_all_tokens()
            }
        except Exception as e:
            result['lexical'] = {
                'valid': False, 
                'error': str(e)
            }
        
        # Análisis sintáctico
        syntax_result = parser.parse(jwt_token)
        result['syntactic'] = syntax_result
        
        # Análisis semántico
        if syntax_result['valid']:
            semantic_result = semantic_analyzer.analyze(
                syntax_result['syntax_tree']
            )
            result['semantic'] = semantic_result
            
            # Verificación criptográfica
            if secret and syntax_result['valid']:
                header_data = parser.extract_component_data(
                    syntax_result['syntax_tree'], 
                    'HEADER'
                )
                if 'alg' in header_data and header_data['alg'] != 'none':
                    parts = jwt_token.split('.')
                    crypto_result = verifier.verify_signature(
                        parts[0], parts[1], parts[2], 
                        header_data['alg'], secret
                    )
                    result['cryptographic'] = crypto_result
                else:
                    result['cryptographic'] = {
                        'valid': False,
                        'error': 'Algoritmo no soportado o ausente'
                    }
        
        # Guardar caso de prueba en MongoDB
        test_cases_collection.insert_one({
            'timestamp': datetime.utcnow(),
            'input_token': jwt_token,
            'secret_provided': bool(secret),
            'results': result
        })
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-cases', methods=['GET'])
def get_test_cases():
    """Obtener casos de prueba almacenados"""
    try:
        cases = list(test_cases_collection.find(
            {}, 
            {'_id': 0}
        ).sort('timestamp', -1).limit(100))
        return jsonify(cases)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Endpoint de salud"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)