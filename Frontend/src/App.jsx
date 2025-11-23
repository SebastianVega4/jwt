import React, { useState, useEffect } from 'react';

const pretty = obj =>
  typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);

// --- Componente principal
function App() {
  // --- Estado para análisis
  const [jwt, setJwt] = useState('');
  const [secret, setSecret] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // --- Estado para generación
  const [headerGen, setHeaderGen] = useState('{"alg":"HS256","typ":"JWT"}');
  const [payloadGen, setPayloadGen] = useState('{"sub":"123456","name":"Ejemplo","iat":1699000000}');
  const [secretGen, setSecretGen] = useState('');
  const [algorithmGen, setAlgorithmGen] = useState('HS256');
  const [jwtGen, setJwtGen] = useState('');
  const [errorGen, setErrorGen] = useState('');
  const [loadingGen, setLoadingGen] = useState(false);

  // --- Estado para historial
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState('');

  // --- Función para cargar historial
  const fetchHistory = async () => {
    setHistoryLoading(true);
    setHistoryError('');
    try {
      const response = await fetch("https://jwtback.vercel.app/api/history");
      const data = await response.json();
      if (response.ok) {
        setHistory(data);
      } else {
        setHistoryError(data.error || 'Error al cargar el historial');
      }
    } catch (e) {
      setHistoryError('No se pudo conectar con el backend para cargar el historial.');
    } finally {
      setHistoryLoading(false);
    }
  }; // End of fetchHistory function

  useEffect(() => {
    fetchHistory();
  }, []); // Empty dependency array means this runs once on mount


  // --- Función de análisis
  const analyzeJWT = async () => {
    setError('');
    setResult(null);
    setLoading(true);
    if (!jwt.trim()) {
      setError("Por favor ingresa un JWT válido.");
      setLoading(false);
      return;
    }
    try {
      const response = await fetch("https://jwtback.vercel.app/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jwt, secret }),
      });
      const data = await response.json();
      setLoading(false);
      if (response.ok) {
        setResult(data);
      } else {
        setError(data.error || 'Error desconocido');
      }
    } catch (e) {
      setLoading(false);
      setError('No se pudo conectar con el backend.');
    }
  };

  // --- Función de generación
  const generateJWT = async () => {
    setErrorGen('');
    setJwtGen('');
    setLoadingGen(true);
    let headerObj, payloadObj;
    try {
      headerObj = JSON.parse(headerGen);
      payloadObj = JSON.parse(payloadGen);
    } catch (e) {
      setErrorGen('Header y/o payload JSON mal formados');
      setLoadingGen(false);
      return;
    }
    try {
      const response = await fetch(
        "https://jwtback.vercel.app/api/generate",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            header: headerObj,
            payload: payloadObj,
            secret: secretGen,
            algorithm: algorithmGen,
          }),
        }
      );
      const data = await response.json();
      setLoadingGen(false);
      if (response.ok) {
        setJwtGen(data.jwt);
      } else {
        setErrorGen(data.error || 'Error desconocido');
      }
    } catch (e) {
      setLoadingGen(false);
      setErrorGen('No se pudo conectar con el backend.');
    }
  };

  return (
    <div style={{
      maxWidth: "720px", margin: "40px auto", background: "#fff",
      borderRadius: "16px", boxShadow: "0 4px 16px #ccc", padding: "32px", fontFamily: "Segoe UI"
      }}>
      <h1 style={{textAlign: "center", fontWeight: 700, letterSpacing: "2px", marginBottom: "40px"}}>🔐 JWT Analyzer & Generator</h1>
      
      {/* ----- Sección análisis ----- */}
      <section style={{marginBottom: 38}}>
        <h2 style={{marginBottom: 12, color: "#313cff"}}>Análisis y validación de JWT</h2>
        <textarea rows={3}
          placeholder="Pega aquí tu JWT"
          style={{ width: "100%", fontSize: "16px", marginBottom: 10, borderRadius: 6, border: "1px solid #ccc", padding: 10 }}
          value={jwt} onChange={e => setJwt(e.target.value)}
        />
        <input type="text"
          placeholder="Clave secreta (opcional)"
          style={{ width: "100%", fontSize: "16px", marginBottom: 10, borderRadius: 6, border: "1px solid #ccc", padding: 10 }}
          value={secret} onChange={e => setSecret(e.target.value)}
        />
        <button
          onClick={analyzeJWT}
          style={{
            fontWeight: 600, fontSize: "16px", padding: "8px 20px",
            background: "#313cff", color: "#fff", border: "none", borderRadius: 8,
            boxShadow: "0 2px 4px #ccc", cursor: "pointer", marginBottom: 8
          }}
        >
          {loading ? "Analizando..." : "Analizar JWT"}
        </button>
        {error && (
          <div style={{ color: "#ba0034", marginTop: 12, fontWeight: 600, fontSize: "16px" }}>{error}</div>
        )}
        {result && (
          <div style={{ marginTop: 28 }}>
            <div>
              <span style={{fontWeight: 600, color: "#1b8700"}}>✓ Estructura: </span>
              {result.estructura_valida ? "Válida" : <span style={{color:"#ba0034"}}>Inválida</span>}
            </div>
            <div style={{marginBottom:10}}><strong>Header:</strong><pre>{pretty(result.header)}</pre></div>
            <div style={{marginBottom:10}}><strong>Payload:</strong><pre>{pretty(result.payload)}</pre></div>
            <div style={{marginBottom:10}}><strong>Árbol de derivación:</strong>
              <pre>{result.arbol_derivacion}</pre>
            </div>
            <div style={{marginBottom:10}}><strong>Claims en payload:</strong>
              <ul>
                {result.payload && typeof result.payload === 'object' &&
                  Object.keys(result.payload).map((c, i) => (
                    <li key={i}><b>{c}</b>: {JSON.stringify(result.payload[c])}</li>)
                )}
              </ul>
            </div>
            <div style={{marginBottom:10}}>
              <b>Errores semánticos:</b>
              <ul style={{ color: "#ba0034" }}>
                {result.errores.length
                  ? result.errores.map((err, idx) => <li key={idx}>{err}</li>)
                  : <li style={{color: "#1b8700"}}>Sin errores.</li>
                }
              </ul>
            </div>
            <div style={{marginBottom:10}}>
              <b>Advertencias:</b>
              <ul style={{ color: "#f7a900" }}>
                {result.warnings.length
                  ? result.warnings.map((warn, idx) => <li key={idx}>{warn}</li>)
                  : <li style={{color: "#1b8700"}}>Sin advertencias.</li>
                }
              </ul>
            </div>
            <div style={{marginBottom:10, fontWeight:500}}>
              Verificación de firma:{" "}
              {typeof result.firma_valida !== "undefined"
                ? (result.firma_valida === true
                  ? <span style={{ color: "#1b8700" }}>✓ Válida</span>
                  : <span style={{ color: "#ba0034" }}>{result.firma_valida === false ? "✗ Inválida" : result.firma_valida}</span>)
                : "No verificada"}
            </div>
          </div>
        )}
      </section>

      {/* ----- Sección generación ----- */}
      <section>
        <h2 style={{marginBottom: 12, color: "#313cff"}}>Generación de JWT</h2>
        <div style={{marginBottom: 8}}>Header JSON:</div>
        <textarea rows={2}
          style={{ width: "100%", fontSize: "16px", marginBottom: 8, borderRadius: 6, border: "1px solid #ccc", padding: 8 }}
          value={headerGen}
          onChange={e => setHeaderGen(e.target.value)}
        />
        <div style={{marginBottom: 8}}>Payload JSON:</div>
        <textarea rows={3}
          style={{ width: "100%", fontSize: "16px", marginBottom: 8, borderRadius: 6, border: "1px solid #ccc", padding: 8 }}
          value={payloadGen}
          onChange={e => setPayloadGen(e.target.value)}
        />
        <div style={{marginBottom: 8}}>Clave secreta:</div>
        <input type="text"
          style={{ width: "100%", fontSize: "16px", marginBottom: 8, borderRadius: 6, border: "1px solid #ccc", padding: 8 }}
          value={secretGen}
          onChange={e => setSecretGen(e.target.value)}
        />
        <div style={{marginBottom: 8}}>Algoritmo:</div>
        <select
          style={{ width: "100%", fontSize: "16px", marginBottom: 15, borderRadius: 6, border: "1px solid #ccc", padding: 8 }}
          value={algorithmGen}
          onChange={e => setAlgorithmGen(e.target.value)}
        >
          <option value="HS256">HS256</option>
          <option value="HS384">HS384</option>
        </select>
        <button
          onClick={generateJWT}
          style={{
            fontWeight: 600, fontSize: "16px", padding: "8px 20px",
            background: "#21ba55", color: "#fff", border: "none", borderRadius: 8,
            boxShadow: "0 2px 4px #ccc", cursor: "pointer", marginBottom: 8
          }}
        >
          {loadingGen ? "Generando..." : "Generar JWT"}
        </button>
        {errorGen && (
          <div style={{ color: "#ba0034", marginTop: 12, fontWeight: 600, fontSize: "16px" }}>{errorGen}</div>
        )}
        {jwtGen && (
  <div style={{
    marginTop: 18,
    background: "#f6fff5",
    border: "1px solid #21ba55",
    borderRadius: 8,
    padding: "18px 14px",
    fontFamily: "monospace",
    boxShadow: "0 0 2px #ccc"
  }}>
    <div style={{fontWeight:600, fontSize:"18px", marginBottom: 8, color: "#0e8f18"}}>
      JWT generado:
    </div>
    <div style={{
      wordBreak: "break-all",
      fontSize: "16px",
      color: "#222",
      overflowX: "auto",
      marginBottom: "6px"
    }}>{jwtGen}</div>
    <button
      onClick={() => navigator.clipboard.writeText(jwtGen)}
      style={{
        fontSize: "13px", background:"#313cff", color:"#fff",
        border:"none", borderRadius:4, padding:"4px 12px",
        cursor:"pointer"
      }}>
      Copiar JWT
    </button>
    <button
      onClick={() => setJwt(jwtGen)}
      style={{
        fontSize: "13px", background:"#0e8f18", color:"#fff",
        border:"none", borderRadius:4, padding:"4px 12px",
        marginLeft:"8px", cursor:"pointer"
      }}>
      Analizar este JWT
    </button>
  </div>
)}

      </section>

      {/* ----- Sección Historial ----- */}
      <section style={{marginTop: 38}}>
        <h2 style={{marginBottom: 12, color: "#313cff"}}>Historial de Análisis de JWT</h2>
        {historyLoading && <p>Cargando historial...</p>}
        {historyError && <div style={{ color: "#ba0034", marginTop: 12, fontWeight: 600, fontSize: "16px" }}>{historyError}</div>}
        {history.length === 0 && !historyLoading && !historyError && <p>No hay historial de análisis aún.</p>}
        {history.length > 0 && (
          <div style={{ maxHeight: "400px", overflowY: "auto", border: "1px solid #eee", borderRadius: 8, padding: 10 }}>
            {history.map((record, index) => (
              <div key={record._id} style={{ marginBottom: 20, paddingBottom: 20, borderBottom: "1px solid #eee" }}>
                <h3 style={{ fontSize: "18px", color: "#555", marginBottom: 10 }}>
                  Análisis #{history.length - index} - {new Date(record.timestamp).toLocaleString()}
                </h3>
                <div style={{ marginBottom: 5 }}>
                  <strong>JWT Analizado:</strong> <pre style={{ wordBreak: "break-all", whiteSpace: "pre-wrap" }}>{record.jwt_string}</pre>
                </div>
                <div style={{ marginBottom: 5 }}>
                  <strong>Estructura Válida:</strong>{" "}
                  {record.analysis_result.estructura_valida ? "Sí" : "No"}
                </div>
                <div style={{ marginBottom: 5 }}>
                  <strong>Header:</strong> <pre>{pretty(record.analysis_result.header)}</pre>
                </div>
                <div style={{ marginBottom: 5 }}>
                  <strong>Payload:</strong> <pre>{pretty(record.analysis_result.payload)}</pre>
                </div>
                <div style={{ marginBottom: 5 }}>
                  <strong>Errores Semánticos:</strong>{" "}
                  {record.analysis_result.errores.length > 0 ? (
                    <ul>
                      {record.analysis_result.errores.map((err, i) => (
                        <li key={i}>{err}</li>
                      ))}
                    </ul>
                  ) : (
                    "Ninguno"
                  )}
                </div>
                <div style={{ marginBottom: 5 }}>
                  <strong>Advertencias:</strong>{" "}
                  {record.analysis_result.warnings.length > 0 ? (
                    <ul>
                      {record.analysis_result.warnings.map((warn, i) => (
                        <li key={i}>{warn}</li>
                      ))}
                    </ul>
                  ) : (
                    "Ninguna"
                  )}
                </div>
                <div style={{ marginBottom: 5 }}>
                  <strong>Firma Válida:</strong>{" "}
                  {typeof record.analysis_result.firma_valida !== "undefined"
                    ? (record.analysis_result.firma_valida === true
                      ? "Válida"
                      : (record.analysis_result.firma_valida === false ? "Inválida" : record.analysis_result.firma_valida))
                    : "No verificada"}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <div style={{marginTop:38, fontSize:"14px", color:"#777"}}>
        <b>Pautas validadas:</b> Estructura, decodificación Base64URL, parsing JSON, visualización de claims, validación semántica, firma HS256/HS384, generación y manejo de errores.
      </div>
    </div>
  );
}

export default App;
