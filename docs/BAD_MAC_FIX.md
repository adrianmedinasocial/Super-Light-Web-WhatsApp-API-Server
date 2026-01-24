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

---

## Fix v2: Mutex Unificado (2025-01-23)

### Problema Persistente
Después de aplicar los fixes anteriores, el error Bad MAC continuaba porque:
1. Había **dos mutexes separados**: uno para `saveCreds()` y otro para operaciones de claves
2. Las operaciones no estaban completamente serializadas
3. Cuando llegaba un prekey bundle, podía haber condiciones de carrera entre:
   - Lectura de claves viejas
   - Cierre de sesión
   - Creación de nueva sesión
   - Escritura de nuevas claves

### Solución v2: Mutex Unificado

**Archivo:** `index.js` (líneas 87-145)

Se unificaron ambos mutexes en uno solo (`sessionMutexes`) que serializa **todas** las operaciones Signal:

```javascript
// ANTES: Dos mutexes separados
const credsMutexes = new Map();  // Para saveCreds
let keyOperationInProgress = false;  // Para keys (local a cada sesión)

// DESPUÉS: Un solo mutex unificado
const sessionMutexes = new Map();  // Para TODAS las operaciones Signal

async function withSessionMutex(sessionId, operationName, fn) {
    const mutex = getSessionMutex(sessionId);
    // Serializa KEY_GET, KEY_SET, y saveCreds
    // ...
}
```

### Cambios en synchronizedKeys

```javascript
// ANTES: Mutex local separado
const executeKeyOperation = async (operation) => { /* mutex local */ };

// DESPUÉS: Usa el mutex global unificado
const synchronizedKeys = {
    get: async (type, ids) => {
        return withSessionMutex(sessionId, `KEY_GET_${type}`, async () => {
            // Lee claves
        });
    },
    set: async (data) => {
        return withSessionMutex(sessionId, 'KEY_SET', async () => {
            await originalKeys.set(data);
            await originalSaveCreds();  // Llama directamente, ya estamos en el mutex
        });
    }
};
```

### Logs de Diagnóstico v2

Con los nuevos cambios, verás estos logs adicionales:

```
[miadriancito] 🔒 Mutex: queuing KEY_GET_session (queue size: 1, waiting for: KEY_SET)
[miadriancito] 🔒 Mutex op #42 (KEY_SET) took 150ms
[miadriancito] 🔒 Mutex: 2 operations still queued
```

Esto indica:
- Las operaciones se están serializando correctamente
- Puedes ver cuántas operaciones están encoladas
- Puedes ver qué operación está bloqueando

### Si el Error Persiste Después de v2

1. **Revisar logs de mutex:**
   - Si ves "Mutex: queuing..." frecuentemente, las operaciones se están serializando
   - Si NO ves estos logs y el error persiste, el problema está en otra parte

2. **Problema con LIDs:**
   - Si los mensajes vienen de `@lid`, el servidor no puede resolver el ID real
   - Esto puede causar problemas con las sesiones Signal

3. **Considerar actualizar Baileys:**
   - La versión actual es 6.7.21
   - Hay disponible 7.0.0-rc.9 que podría tener mejoras
   - Nota: Es un release candidate, revisar changelog antes de actualizar

4. **Eliminar sesión y empezar de nuevo:**
   - A veces las sesiones Signal quedan irrecuperablemente corruptas
   - Eliminar la carpeta de la sesión y escanear el QR de nuevo

---

## Fix v3: Deduplicación Inteligente (2025-01-23)

### Problema Descubierto
Después del fix v2, se descubrió un problema crítico: **algunos mensajes nunca llegaban al backend**.

**Patrón observado:**
```
📱 Celular envía "papi" → ❌ Nunca llega al backend
📱 Celular envía "mami" → ✅ Llega correctamente
```

**Causa raíz:**
Cuando un mensaje fallaba con Bad MAC, el sistema de deduplicación lo marcaba como "procesado" aunque no se había desencriptado. Cuando WhatsApp reenviaba el mensaje después del retry request, el código lo detectaba como duplicado y lo descartaba.

**Flujo problemático:**
1. Mensaje "papi" llega → Bad MAC → falla desencriptar
2. Código marca `messageId` como procesado (ERROR!)
3. Baileys envía retry request a WhatsApp
4. WhatsApp reenvía "papi"
5. Código ve que `messageId` ya está procesado → **DESCARTA EL MENSAJE**
6. "papi" nunca llega al backend

### Solución v3: Verificación de Contenido

**Archivo:** `index.js` (evento `messages.upsert`)

Ahora se verifica si el mensaje tiene contenido real antes de marcarlo como procesado:

```javascript
// 🔧 FIX v3: Check if message was decrypted successfully
const messageContent = msg.message;
const hasRealContent = messageContent && (
    messageContent.conversation ||
    messageContent.extendedTextMessage ||
    messageContent.imageMessage ||
    messageContent.videoMessage ||
    messageContent.audioMessage ||
    messageContent.documentMessage ||
    // ... otros tipos de mensaje
);

// Si no tiene contenido real, NO marcar como procesado
if (!hasRealContent) {
    log(`⚠️ Message ${messageId} has no decryptable content, skipping dedup`);
    // Permite que el retry sea procesado cuando llegue
} else {
    // Solo marcar como procesado si tiene contenido real
    if (processedMessages.has(messageId)) {
        return; // Skip duplicate
    }
    processedMessages.set(messageId, Date.now());
}

// Solo enviar al webhook si tiene contenido real
if (hasRealContent) {
    await postToWebhook(messageData);
} else {
    log(`⏭️ Skipping webhook - waiting for retry`);
}
```

### Logs de Diagnóstico v3

Con los nuevos cambios, verás estos logs cuando un mensaje falla:

```
[miadriancito] ⚠️ Message ABC123 has no decryptable content (type: senderKeyDistributionMessage), skipping dedup registration
[miadriancito] ⏭️ Skipping webhook for message ABC123 - no decryptable content (waiting for retry)
```

Y cuando llega el retry:

```
[miadriancito] 🔑 KEY GET [session]: requested 1 keys, found 1
[miadriancito] Received text message from 5215547606478@s.whatsapp.net
[SYSTEM] Successfully posted to webhook
```

### Tipos de Mensaje Reconocidos

El sistema ahora reconoce estos tipos de contenido como "mensaje válido":
- `conversation` - Texto simple
- `extendedTextMessage` - Texto con formato/links
- `imageMessage` - Imágenes
- `videoMessage` - Videos
- `audioMessage` - Audio/notas de voz
- `documentMessage` - Documentos
- `stickerMessage` - Stickers
- `contactMessage` - Contactos
- `locationMessage` - Ubicaciones
- `reactionMessage` - Reacciones
- `pollCreationMessage` - Encuestas
- `listMessage` - Listas
- `buttonsMessage` - Botones
- `templateMessage` - Templates

### Resumen de Cambios v3

| Antes | Después |
|-------|---------|
| Todo mensaje marcado como procesado | Solo mensajes con contenido real |
| Retry descartado como duplicado | Retry procesado correctamente |
| Algunos mensajes nunca llegaban | Todos los mensajes llegan |

---

## Fix v4: Mapeo de LID Persistente (2025-01-23)

### Problema Descubierto
Después de los fixes anteriores, se descubrió que **el mismo usuario aparecía como dos conversaciones diferentes** en el backend:
- Conversación 1: `5215547606478@s.whatsapp.net` (número real)
- Conversación 2: `227599578050572@lid` (LID no resuelto)

**Causa raíz:**
1. Baileys 6.7.21 **no tiene soporte nativo de LID mapping** (`signalRepository.lidMapping` no existe)
2. Cuando hay Bad MAC, el mensaje llega sin `contextInfo` ni `participant`, por lo que el LID no se puede resolver
3. Había un **listener duplicado** de `creds.update` que causaba race conditions

### Solución v4: Dos Cambios

#### Cambio 1: Eliminar Listener Duplicado
**Archivo:** `index.js`

```javascript
// ANTES: Dos listeners (causaba race conditions)
sock.ev.process(async (events) => {
    if (events['creds.update']) { await saveCreds(); }
});
sock.ev.on('creds.update', saveCreds);  // DUPLICADO!

// DESPUÉS: Solo un listener
sock.ev.process(async (events) => {
    if (events['creds.update']) { await saveCreds(); }
});
// Listener duplicado ELIMINADO
```

#### Cambio 2: Cache Local de LID → Número Real
**Archivo:** `index.js`

Se implementó un mapa global `lidToPhoneMap` que:
1. Guarda la relación LID → número real cuando un mensaje se resuelve correctamente
2. Consulta el cache PRIMERO cuando llega un mensaje con LID
3. Se limpia automáticamente después de 24 horas

```javascript
// Mapa global
const lidToPhoneMap = new Map();
const LID_MAP_TTL = 24 * 60 * 60 * 1000; // 24 hours

// En extractRealPhoneNumber():
// 1. Primero busca en cache local
const cachedPhone = lidToPhoneMap.get(from);
if (cachedPhone) {
    from = cachedPhone.phone;
    log(`🎯 LID resolved via LOCAL CACHE: ${from}`);
}

// 2. Si se resuelve por otro método, guarda en cache
if (!from.includes('@lid') && originalFrom.includes('@lid')) {
    lidToPhoneMap.set(originalFrom, { phone: from, timestamp: Date.now() });
    log(`💾 LID mapping saved: ${originalFrom} → ${from}`);
}
```

### Logs de Diagnóstico v4

Con los nuevos cambios, verás estos logs:

```
[sessionId] 🎯 LID resolved via LOCAL CACHE: 5215547606478@s.whatsapp.net (cached 45s ago)
[sessionId] 💾 LID mapping saved: 227599578050572@lid → 5215547606478@s.whatsapp.net
[sessionId] 🧹 Cleaned 3 expired LID mappings from cache
```

### Payload del Webhook v4

El webhook ahora incluye `originalLID` para que el backend pueda mantener su propio mapeo:

```json
{
  "event": "new-message",
  "from": "5215547606478@s.whatsapp.net",
  "originalLID": "227599578050572@lid",
  "isLID": false,
  ...
}
```

### Limitación del Cache Local (Servidor)

El cache del servidor solo funciona **después** de que un mensaje con número real resuelto haya llegado. Si el primer mensaje de un usuario tiene Bad MAC y no se puede resolver, el backend recibirá el LID.

Para resolver esta limitación, se implementó un **mapeo persistente en el backend**.

---

## Fix v4 Backend: Mapeo LID Persistente en Base de Datos

### Problema
El cache local del servidor WhatsApp se pierde cuando:
1. El servidor se reinicia
2. El cache TTL de 24 horas expira
3. El primer mensaje de un usuario tiene Bad MAC

### Solución: Mapeo Persistente en SQLite

#### 1. Nueva Tabla `lid_phone_mapping`
**Archivo:** `src/db/auto-migrate.js` (Migración 033)

```sql
CREATE TABLE lid_phone_mapping (
    id TEXT PRIMARY KEY,
    lid TEXT NOT NULL UNIQUE,
    phone_number TEXT NOT NULL,
    session_id TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_lid_mapping_lid ON lid_phone_mapping(lid);
CREATE INDEX idx_lid_mapping_phone ON lid_phone_mapping(phone_number);
```

#### 2. Guardar Mapeo cuando llega `originalLID`
**Archivo:** `src/routes/webhook.js`

```javascript
function saveLidMapping(lid, phoneNumber, sessionId = null) {
    const db = getDatabase();
    const now = new Date().toISOString();

    // UPSERT: actualiza si ya existe
    db.prepare(`
        INSERT INTO lid_phone_mapping (id, lid, phone_number, session_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(lid) DO UPDATE SET
            phone_number = excluded.phone_number,
            session_id = excluded.session_id,
            updated_at = excluded.updated_at
    `).run(generateId(), lid, phoneNumber, sessionId, now, now);

    console.log(`💾 LID mapping guardado: ${lid} → ${phoneNumber}`);
}

// En el webhook handler:
const originalLID = event?.originalLID;
if (originalLID && !from.includes('@lid')) {
    saveLidMapping(originalLID, from, sessionId);
}
```

#### 3. Resolver LID desde BD en `extractFrom()`
**Archivo:** `src/routes/webhook.js`

```javascript
function getPhoneFromLid(lid) {
    const db = getDatabase();
    const mapping = db.prepare(`
        SELECT phone_number FROM lid_phone_mapping WHERE lid = ?
    `).get(lid);

    if (mapping) {
        console.log(`🎯 LID resuelto via DB: ${lid} → ${mapping.phone_number}`);
        return mapping.phone_number;
    }
    return null;
}

// En extractFrom():
// INTENTO 5 - Buscar en mapeo LID → número de la BD
if (remoteJid && remoteJid.includes("@lid")) {
    const mappedPhone = getPhoneFromLid(remoteJid);
    if (mappedPhone) {
        console.log(`🎯 LID resuelto via mapeo DB: ${remoteJid} → ${mappedPhone}`);
        return mappedPhone;
    }
}
```

#### 4. Unificar Conversaciones en `getOrCreateConversation()`
**Archivo:** `src/services/conversationMemory.js`

```javascript
function getPhoneFromLidMapping(lid) {
    const db = getDatabase();
    const mapping = db.prepare(`
        SELECT phone_number FROM lid_phone_mapping WHERE lid = ?
    `).get(lid);
    return mapping?.phone_number || null;
}

export function getOrCreateConversation(userPhone, businessId, userName = null) {
    const db = getDatabase();

    // �� FIX v4: Si es LID, buscar si ya tenemos el número real mapeado
    if (userPhone.includes("@lid")) {
        const mappedPhone = getPhoneFromLidMapping(userPhone);
        if (mappedPhone) {
            console.log(`🔗 LID ${userPhone} tiene mapeo a ${mappedPhone}`);

            // Verificar si existe conversación con el número real
            const realConvId = `${mappedPhone}_${businessId}`;
            const realConv = db.prepare(`
                SELECT id FROM conversations WHERE id = ?
            `).get(realConvId);

            if (realConv) {
                console.log(`🎯 Usando conversación existente con número real: ${realConvId}`);
                userPhone = mappedPhone; // Usar el número real
            }
        }
    }

    // ... resto de la función
}
```

### Logs de Diagnóstico Backend

```
💾 LID mapping guardado: 227599578050572@lid → 5215547606478
🎯 LID resuelto via DB: 227599578050572@lid → 5215547606478
🎯 LID resuelto via mapeo DB: 227599578050572@lid → 5215547606478
🔗 LID 227599578050572@lid tiene mapeo a 5215547606478
🎯 Usando conversación existente con número real: 5215547606478_businessId
```

### Flujo Completo v4

```
┌─────────────────────────────────────────────────────────────────────┐
│                     SERVIDOR WHATSAPP (serverbayles)                │
├─────────────────────────────────────────────────────────────────────┤
│  1. Mensaje llega con LID                                           │
│  2. Busca en cache local (lidToPhoneMap)                           │
│  3. Si encuentra → usa número real                                  │
│  4. Si resuelve por contextInfo → guarda en cache                  │
│  5. Envía webhook con { from: número, originalLID: lid }           │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     BACKEND (booking-backend)                        │
├─────────────────────────────────────────────────────────────────────┤
│  1. Recibe webhook                                                  │
│  2. Si tiene originalLID + número real → guarda en BD              │
│  3. extractFrom() busca en BD si llega solo LID                    │
│  4. getOrCreateConversation() unifica usando mapeo BD              │
│  5. Conversación única por usuario (número real)                   │
└─────────────────────────────────────────────────────────────────────┘
```

### Ventajas del Mapeo Persistente

| Aspecto | Cache Servidor | BD Backend |
|---------|---------------|------------|
| Persistencia | ❌ Se pierde en restart | ✅ Permanente |
| TTL | 24 horas | ♾️ Sin expiración |
| Primer mensaje | ❌ No funciona | ✅ Funciona si ya existe mapeo |
| Escalabilidad | Un servidor | Cualquier instancia |

---

## Commits Relacionados

### Servidor WhatsApp (serverbayles)
1. `d5fb4d7` - Add mutex and debounce to saveCreds
2. `ecd5ba7` - Create Express sessions directory if not exists
3. `156cdfc` - Add ev.process() for synchronous event handling
4. `a908f2d` - Reuse existing token on session restoration
5. `14888f1` - Remove key caching and add mutex for Signal key operations
6. `1456d7e` - Unify all Signal operation mutexes (v2 fix)
7. `e33843d` - Don't mark failed decryption messages as processed (v3 fix)
8. `cd633e7` - Remove duplicate creds.update listener + LID cache (v4 fix)

### Backend (booking-backend)
9. `e983297` - Fix v4 Backend: LID to phone mapping for unified conversations

## Referencias

- [Baileys Issue #123 - Bad MAC errors](https://github.com/WhiskeySockets/Baileys/issues)
- [Signal Protocol - Ratchet](https://signal.org/docs/specifications/doubleratchet/)
- [libsignal - Session management](https://github.com/nickclaw/libsignal/)
