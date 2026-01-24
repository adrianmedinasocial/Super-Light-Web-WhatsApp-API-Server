# Fix: Bad MAC Error en WhatsApp Baileys

## Problema

Los mensajes entrantes de WhatsApp fallaban intermitentemente con el error:

```
Failed to decrypt message with any known session...
Session error: Error: Bad MAC
    at Object.verifyMAC (/app/node_modules/libsignal/src/crypto.js:87:15)
    at SessionCipher.doDecryptWhisperMessage (...)
```

**Síntomas:**
- Un mensaje llegaba correctamente, el siguiente fallaba
- Después del error, WhatsApp enviaba un "prekey bundle" nuevo
- El mensaje siguiente al prekey bundle llegaba bien
- Ciclo repetitivo: OK → Bad MAC → Prekey Bundle → OK → Bad MAC...

## Causa Raíz

El problema tenía múltiples causas relacionadas con la sincronización de claves Signal:

### 1. Cache de Claves Desactualizado
`makeCacheableSignalKeyStore` de Baileys cachea las claves Signal en memoria. Cuando múltiples mensajes llegan simultáneamente:
- Mensaje 1 usa clave v1 del cache
- Mensaje 1 actualiza la clave a v2 en disco
- Mensaje 2 usa clave v1 del cache (desactualizada) → **Bad MAC**

### 2. Escrituras Concurrentes de Credenciales
`saveCreds()` se llamaba sin protección de concurrencia:
- Dos mensajes llegan al mismo tiempo
- Ambos intentan escribir credenciales simultáneamente
- Las claves Signal se corrompen parcialmente

### 3. Token de API Regenerado en Restart
Cuando Railway reiniciaba el servidor:
- Se cargaban los tokens del disco correctamente
- Pero `createSession()` generaba un **nuevo token** con `randomUUID()`
- El backend seguía usando el token viejo → `Invalid token`

## Solución Implementada

### Cambio 1: Mutex para saveCreds
**Archivo:** `index.js` (líneas 87-130)

```javascript
// Sistema de mutex para proteger escrituras de credenciales
const credsMutexes = new Map();

function createCredsMutex(sessionId) { ... }
async function withCredsMutex(sessionId, fn) { ... }
```

Esto asegura que solo una operación de escritura de credenciales ocurra a la vez por sesión.

### Cambio 2: Eliminación del Cache de Claves
**Archivo:** `index.js` (líneas 936-993)

**Antes:**
```javascript
keys: makeCacheableSignalKeyStore(state.keys, logger)
```

**Después:**
```javascript
// Mutex para operaciones de claves
const executeKeyOperation = async (operation) => { ... };

const synchronizedKeys = {
    get: async (type, ids) => {
        return executeKeyOperation(async () => {
            // Lee directamente del disco
            const result = await originalKeys.get(type, ids);
            return result;
        });
    },
    set: async (data) => {
        return executeKeyOperation(async () => {
            await originalKeys.set(data);
            await saveCreds(); // Guarda inmediatamente
        });
    }
};

// Usa claves sincronizadas SIN cache
keys: synchronizedKeys
```

### Cambio 3: Reutilización de Token en Restart
**Archivo:** `index.js` (líneas 1434-1445)

**Antes:**
```javascript
const token = randomUUID();
sessionTokens.set(sessionId, token);
```

**Después:**
```javascript
let token = sessionTokens.get(sessionId);
if (!token) {
    token = randomUUID();
    sessionTokens.set(sessionId, token);
    log(`🔑 Generated new token for session ${sessionId}`);
} else {
    log(`🔑 Reusing existing token for session ${sessionId}`);
}
```

### Cambio 4: Directorio de Sesiones Express
**Archivo:** `index.js` (líneas 376-382)

```javascript
const EXPRESS_SESSIONS_DIR = path.join(DATA_DIR, 'sessions');
if (!fs.existsSync(EXPRESS_SESSIONS_DIR)) {
    fs.mkdirSync(EXPRESS_SESSIONS_DIR, { recursive: true });
}
```

Esto evita el error `ENOENT` de `session-file-store`.

## Configuración Requerida en Railway

### Variables de Entorno
```env
DATA_DIR=/app/auth_info_baileys
SESSIONS_DIR=/app/auth_info_baileys
TOKEN_ENCRYPTION_KEY=<64-char-hex-key>
SESSION_SECRET=<random-secret>
```

### Volumen Persistente
- **Mount Path:** `/app/auth_info_baileys`
- **Tamaño:** 5 GB (mínimo recomendado)

Sin el volumen persistente, las claves Signal se pierden en cada deploy.

## Logs de Diagnóstico

Con los cambios, verás estos logs:

```
🔑 KEY GET [session]: requested 1 keys, found 1
🔑 KEY SET [session]: saving 1 keys
🔑 KEY SET: credentials saved to disk
🔑 Reusing existing token for session miadriancito
```

Si ves `found 0` cuando debería haber claves, hay un problema de persistencia.

## Si el Problema Persiste

Si después de estos cambios el error "Bad MAC" continúa:

1. **Eliminar y recrear la sesión:**
   - Eliminar la sesión desde el dashboard
   - Escanear el QR nuevamente
   - Esto genera claves Signal completamente nuevas

2. **Verificar dispositivos vinculados:**
   - Si el número de WhatsApp tiene múltiples dispositivos vinculados (WhatsApp Web, Desktop, etc.), pueden competir por las claves Signal
   - Desvincular otros dispositivos puede ayudar

3. **Verificar volumen en Railway:**
   - Asegurarse de que el volumen está correctamente montado
   - Verificar que los archivos persisten entre deploys

## Commits Relacionados

1. `d5fb4d7` - Add mutex and debounce to saveCreds
2. `ecd5ba7` - Create Express sessions directory if not exists
3. `156cdfc` - Add ev.process() for synchronous event handling
4. `a908f2d` - Reuse existing token on session restoration
5. `14888f1` - Remove key caching and add mutex for Signal key operations

## Referencias

- [Baileys Issue #123 - Bad MAC errors](https://github.com/WhiskeySockets/Baileys/issues)
- [Signal Protocol - Ratchet](https://signal.org/docs/specifications/doubleratchet/)
- [libsignal - Session management](https://github.com/nickclaw/libsignal/)
