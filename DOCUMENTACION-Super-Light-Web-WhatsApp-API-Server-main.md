# 📚 DOCUMENTACIÓN - Super Light WhatsApp API Server

## 1. DESCRIPCIÓN GENERAL

Este proyecto es un servidor de API para WhatsApp Web basado en **Baileys** (@whiskeysockets/baileys), que permite:

- ✅ Gestión de múltiples sesiones de WhatsApp
- ✅ Autenticación mediante código QR
- ✅ Envío de mensajes (texto, imágenes, documentos)
- ✅ Sistema de campañas masivas
- ✅ Webhooks para eventos
- ✅ Panel de administración web
- ✅ Sistema multiusuario con roles

**Versión:** 3.0.4
**Tecnologías:** Node.js, Express, Baileys, WebSocket, SQLite

---

## 2. ARQUITECTURA DEL PROYECTO

```
index.js          → Servidor principal (Express + WebSocket + Baileys)
api_v1.js         → Endpoints REST API v1 (autenticados)
legacy_api.js     → Endpoints legacy (sin autenticación)
users.js          → Gestión de usuarios y autenticación
campaigns.js      → Sistema de campañas
campaign-sender.js → Motor de envío de campañas
activity-logger.js → Registro de actividades
admin/            → Dashboard web (HTML/CSS/JS)
auth_info_baileys/ → Almacenamiento de sesiones WhatsApp
```

---

## 3. GENERACIÓN DEL CÓDIGO QR ⚡

### 3.1 Flujo de Generación

```
Cliente crea sesión → Baileys inicia conexión → Se genera QR →
QR guardado en session.qr → Broadcast vía WebSocket →
Cliente renderiza QR → Usuario escanea → Sesión autenticada
```

### 3.2 Código Responsable (index.js)

**Líneas 784-793 - Evento de conexión:**
```javascript
sock.ev.on('connection.update', (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr) {
        log('QR code generated.', sessionId);
        // El QR viene como string de Baileys
        updateSessionState(sessionId, 'GENERATING_QR', 'QR code available.', qr, '');
    }

    if (connection === 'open') {
        log('Connection opened.', sessionId);
        // Sesión conectada
    }
});
```

**Líneas 565-593 - Actualización de estado:**
```javascript
function updateSessionState(sessionId, status, detail = '', qr = null, number = '') {
    const ses = activeSessions.find(s => s.sessionId === sessionId);
    if (ses) {
        ses.status = status;
        ses.detail = detail;
        ses.qr = qr;  // ← Aquí se almacena el QR
        ses.number = number;

        // Broadcast a todos los clientes conectados
        broadcast({
            type: 'session-update',
            data: activeSessions
        });
    }
}
```

### 3.3 Renderización en el Dashboard (admin/dashboard.html)

**Líneas 817-821 - Renderizado del QR:**
```javascript
if (session.status === 'GENERATING_QR' && session.qr) {
    qrContainer.style.display = 'block';
    getQrBtn.style.display = 'none';
    qrCodeEl.innerHTML = '';
    // Usa la librería qrcode.min.js
    new QRCode(qrCodeEl, { text: session.qr, width: 200, height: 200 });
}
```

**Librería utilizada:** `qrcode.min.js` (incluida en `admin/js/`)

---

## 4. RECUPERACIÓN DEL QR VÍA API 🔑

### 4.1 Método Recomendado: GET /api/v1/sessions

Este endpoint devuelve todas las sesiones con sus códigos QR en tiempo real.

**Request:**
```bash
curl -X GET 'http://localhost:3000/api/v1/sessions'
```

**Response:**
```json
[
    {
        "sessionId": "mi_sesion",
        "status": "GENERATING_QR",
        "detail": "QR code available.",
        "qr": "2@Fq8X... (string del código QR)",
        "token": "abc123-token-456",
        "owner": "usuario@example.com"
    },
    {
        "sessionId": "otra_sesion",
        "status": "CONNECTED",
        "detail": "Connected as +1234567890",
        "qr": null,
        "token": "xyz789-token",
        "owner": "admin@localhost"
    }
]
```

**Campos importantes:**
- `status`: `"GENERATING_QR"`, `"CONNECTED"`, `"DISCONNECTED"`, `"INITIAL"`
- `qr`: String con los datos del QR (solo cuando status es `GENERATING_QR`)
- `token`: Token de sesión para enviar mensajes

### 4.2 Método Alternativo: WebSocket

Para recibir actualizaciones en tiempo real:

**1. Obtener token de autenticación:**
```javascript
const response = await fetch('/api/v1/ws-auth', {
    credentials: 'same-origin'
});
const { wsToken } = await response.json();
```

**2. Conectar WebSocket:**
```javascript
const ws = new WebSocket(`ws://localhost:3000?token=${wsToken}`);

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);

    if (data.type === 'session-update') {
        data.data.forEach(session => {
            if (session.status === 'GENERATING_QR' && session.qr) {
                console.log(`QR para ${session.sessionId}:`, session.qr);
                renderizarQR(session.qr);
            }
        });
    }
};
```

**3. Tipos de mensajes WebSocket:**
```javascript
{
    type: 'session-update',      // Actualización de sesiones
    data: [...]                  // Array de sesiones
}

{
    type: 'incoming-message',    // Mensaje recibido
    sessionId: 'xxx',
    message: {...}
}
```

### 4.3 Procesamiento del QR en Diferentes Entornos

#### **A) En el navegador (HTML/JavaScript):**
```html
<!DOCTYPE html>
<html>
<head>
    <script src="https://cdn.jsdelivr.net/npm/qrcode/build/qrcode.min.js"></script>
</head>
<body>
    <div id="qr-container"></div>

    <script>
        async function obtenerYMostrarQR() {
            const response = await fetch('/api/v1/sessions');
            const sessions = await response.json();

            const miSesion = sessions.find(s => s.sessionId === 'mi_sesion');

            if (miSesion && miSesion.qr) {
                const container = document.getElementById('qr-container');
                new QRCode(container, {
                    text: miSesion.qr,
                    width: 256,
                    height: 256
                });
            }
        }

        obtenerYMostrarQR();
    </script>
</body>
</html>
```

#### **B) En Node.js (generar imagen):**
```bash
npm install qrcode
```

```javascript
const QRCode = require('qrcode');
const axios = require('axios');

async function generarImagenQR() {
    const response = await axios.get('http://localhost:3000/api/v1/sessions');
    const sessions = response.data;

    const miSesion = sessions.find(s => s.sessionId === 'mi_sesion');

    if (miSesion && miSesion.qr) {
        // Guardar como archivo PNG
        await QRCode.toFile('whatsapp-qr.png', miSesion.qr);

        // O generar Data URL para usar en <img src="...">
        const dataURL = await QRCode.toDataURL(miSesion.qr);
        console.log(dataURL);
    }
}

generarImagenQR();
```

#### **C) En Python:**
```python
import requests
import qrcode

response = requests.get('http://localhost:3000/api/v1/sessions')
sessions = response.json()

mi_sesion = next((s for s in sessions if s['sessionId'] == 'mi_sesion'), None)

if mi_sesion and mi_sesion.get('qr'):
    qr = qrcode.QRCode()
    qr.add_data(mi_sesion['qr'])
    qr.make()
    img = qr.make_image()
    img.save('whatsapp-qr.png')
```

---

## 5. ENDPOINTS DE API COMPLETOS

### 5.1 Gestión de Sesiones

| Método | Endpoint | Auth | Descripción |
|--------|----------|------|-------------|
| **POST** | `/api/v1/sessions` | Master API Key | Crear nueva sesión |
| **GET** | `/api/v1/sessions` | Ninguna | Listar todas las sesiones (incluye QR) |
| **DELETE** | `/api/v1/sessions/:sessionId` | Bearer Token | Eliminar sesión |
| **GET** | `/api/v1/sessions/:sessionId/qr` | Cookie | Regenerar QR |

**Ejemplo - Crear sesión:**
```bash
curl -X POST 'http://localhost:3000/api/v1/sessions' \
  -H 'X-Master-Key: tu_master_api_key' \
  -H 'Content-Type: application/json' \
  -d '{
    "sessionId": "cliente_123"
  }'
```

**Response:**
```json
{
    "status": "success",
    "message": "Session cliente_123 created.",
    "token": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 5.2 Envío de Mensajes

| Método | Endpoint | Auth | Descripción |
|--------|----------|------|-------------|
| **POST** | `/api/v1/messages?sessionId=xxx` | Bearer Token | Enviar mensaje |
| **DELETE** | `/api/v1/message` | Bearer Token | Eliminar mensaje |

**Ejemplo - Enviar mensaje de texto:**
```bash
curl -X POST 'http://localhost:3000/api/v1/messages?sessionId=cliente_123' \
  -H 'Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000' \
  -H 'Content-Type: application/json' \
  -d '{
    "to": "1234567890",
    "text": "Hola desde la API!"
  }'
```

**Ejemplo - Enviar imagen con texto:**
```bash
curl -X POST 'http://localhost:3000/api/v1/messages?sessionId=cliente_123' \
  -H 'Authorization: Bearer 550e8400-...' \
  -H 'Content-Type: application/json' \
  -d '{
    "to": "1234567890",
    "text": "Mira esta imagen",
    "imageUrl": "https://ejemplo.com/imagen.jpg"
  }'
```

**Ejemplo - Enviar documento:**
```bash
curl -X POST 'http://localhost:3000/api/v1/messages?sessionId=cliente_123' \
  -H 'Authorization: Bearer 550e8400-...' \
  -H 'Content-Type: application/json' \
  -d '{
    "to": "1234567890",
    "documentUrl": "https://ejemplo.com/documento.pdf"
  }'
```

### 5.3 Webhooks

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| **POST** | `/api/v1/webhook` | Configurar webhook |
| **GET** | `/api/v1/webhook?sessionId=xxx` | Obtener webhook |
| **DELETE** | `/api/v1/webhook` | Eliminar webhook |

**Ejemplo - Configurar webhook:**
```bash
curl -X POST 'http://localhost:3000/api/v1/webhook' \
  -H 'Authorization: Bearer 550e8400-...' \
  -H 'Content-Type: application/json' \
  -d '{
    "sessionId": "cliente_123",
    "webhookUrl": "https://mi-servidor.com/webhook"
  }'
```

**Eventos que se envían al webhook:**
```json
{
    "event": "message",
    "sessionId": "cliente_123",
    "from": "1234567890@s.whatsapp.net",
    "body": "Texto del mensaje",
    "timestamp": 1234567890,
    "hasMedia": false
}
```

### 5.4 Campañas

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| **GET** | `/api/v1/campaigns` | Listar campañas |
| **POST** | `/api/v1/campaigns` | Crear campaña |
| **POST** | `/api/v1/campaigns/:id/send` | Iniciar envío |
| **POST** | `/api/v1/campaigns/:id/pause` | Pausar campaña |
| **POST** | `/api/v1/campaigns/:id/resume` | Reanudar |
| **GET** | `/api/v1/campaigns/:id/export` | Exportar resultados CSV |
| **GET** | `/api/v1/campaigns/csv-template` | Descargar plantilla CSV |

**Ejemplo - Crear campaña:**
```bash
curl -X POST 'http://localhost:3000/api/v1/campaigns' \
  -H 'Cookie: connect.sid=...' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Campaña Navidad 2025",
    "sessionId": "cliente_123",
    "message": "Hola {{nombre}}, feliz navidad!",
    "recipients": [
        {"name": "Juan", "phone": "1234567890"},
        {"name": "María", "phone": "0987654321"}
    ],
    "delayBetweenMessages": 3000,
    "delayBetweenBatches": 10000
  }'
```

### 5.5 Gestión de Usuarios (Admin)

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| **GET** | `/api/v1/users` | Listar usuarios |
| **POST** | `/api/v1/users` | Crear usuario |
| **PUT** | `/api/v1/users/:email` | Actualizar usuario |
| **DELETE** | `/api/v1/users/:email` | Eliminar usuario |

---

## 6. EJEMPLO COMPLETO: DE CERO A ENVIAR MENSAJE

```javascript
const axios = require('axios');
const QRCode = require('qrcode');

const BASE_URL = 'http://localhost:3000';
const MASTER_KEY = 'tu_master_api_key';
const SESSION_ID = 'mi_app_123';

async function flujoCompleto() {
    // 1. Crear sesión
    console.log('1. Creando sesión...');
    const createResponse = await axios.post(
        `${BASE_URL}/api/v1/sessions`,
        { sessionId: SESSION_ID },
        { headers: { 'X-Master-Key': MASTER_KEY } }
    );

    const sessionToken = createResponse.data.token;
    console.log('✓ Sesión creada, token:', sessionToken);

    // 2. Esperar y obtener QR
    console.log('2. Esperando generación del QR...');
    let qrData = null;
    let intentos = 0;

    while (!qrData && intentos < 30) {
        await new Promise(resolve => setTimeout(resolve, 2000));

        const sessionsResponse = await axios.get(`${BASE_URL}/api/v1/sessions`);
        const miSesion = sessionsResponse.data.find(s => s.sessionId === SESSION_ID);

        if (miSesion && miSesion.status === 'GENERATING_QR' && miSesion.qr) {
            qrData = miSesion.qr;
        }
        intentos++;
    }

    if (!qrData) {
        throw new Error('No se generó el QR en el tiempo esperado');
    }

    console.log('✓ QR generado');

    // 3. Generar imagen del QR
    await QRCode.toFile('whatsapp-qr.png', qrData);
    console.log('✓ QR guardado en whatsapp-qr.png');
    console.log('  → Escanea el código QR con tu teléfono');

    // 4. Esperar conexión
    console.log('4. Esperando autenticación...');
    let conectado = false;
    intentos = 0;

    while (!conectado && intentos < 60) {
        await new Promise(resolve => setTimeout(resolve, 2000));

        const sessionsResponse = await axios.get(`${BASE_URL}/api/v1/sessions`);
        const miSesion = sessionsResponse.data.find(s => s.sessionId === SESSION_ID);

        if (miSesion && miSesion.status === 'CONNECTED') {
            conectado = true;
            console.log('✓ Sesión conectada como:', miSesion.detail);
        }
        intentos++;
    }

    if (!conectado) {
        throw new Error('No se pudo conectar la sesión');
    }

    // 5. Enviar mensaje de prueba
    console.log('5. Enviando mensaje de prueba...');
    await axios.post(
        `${BASE_URL}/api/v1/messages?sessionId=${SESSION_ID}`,
        {
            to: '1234567890',  // Reemplaza con número real
            text: '¡Hola desde la API de WhatsApp!'
        },
        {
            headers: { 'Authorization': `Bearer ${sessionToken}` }
        }
    );

    console.log('✓ Mensaje enviado exitosamente');
    console.log('\n🎉 Flujo completo ejecutado con éxito');
}

flujoCompleto().catch(console.error);
```

---

## 7. CONFIGURACIÓN DEL SERVIDOR

### 7.1 Variables de Entorno (.env)

```env
# Puerto del servidor
PORT=3000

# Contraseña del dashboard admin
ADMIN_DASHBOARD_PASSWORD=admin123

# Clave maestra para crear sesiones
MASTER_API_KEY=mi_clave_super_secreta

# Clave de encriptación (64 caracteres hexadecimales)
TOKEN_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# URL del webhook global (opcional)
WEBHOOK_URL=https://mi-servidor.com/webhook

# Límite de sesiones concurrentes
MAX_SESSIONS=10

# Tiempo de expiración de sesiones en horas
SESSION_TIMEOUT_HOURS=24

# Entorno
NODE_ENV=production
```

### 7.2 Instalación

```bash
# Clonar o descargar el proyecto
cd Super-Light-Web-WhatsApp-API-Server

# Instalar dependencias
npm install

# Crear archivo .env
cp .env.example .env
nano .env  # Editar configuración

# Iniciar servidor
npm start
```

### 7.3 Ejecución con PM2 (Producción)

```bash
npm install -g pm2

pm2 start index.js --name whatsapp-api
pm2 save
pm2 startup
```

---

## 8. SEGURIDAD Y BUENAS PRÁCTICAS

### 8.1 Autenticación

**Niveles de autenticación:**

1. **Master API Key** (para crear sesiones)
   - Configurada en variable `MASTER_API_KEY`
   - Se envía en header `X-Master-Key`

2. **Bearer Token** (para usar sesiones)
   - Generado al crear la sesión
   - Se envía en header `Authorization: Bearer <token>`
   - Almacenado encriptado con AES-256-CBC

3. **Cookies de sesión** (para dashboard web)
   - Sistema de login con email/contraseña
   - Roles: `admin` y `user`
   - Hasheado con bcrypt

### 8.2 Límites y Restricciones

**Archivos:**
- Tamaño máximo: 25MB
- Formatos permitidos: JPG, PNG, GIF, PDF, DOCX, XLSX

**Campañas:**
- Delay entre mensajes: mínimo 1000ms (recomendado 3000ms)
- Delay entre batches: mínimo 5000ms (recomendado 10000ms)

### 8.3 Manejo de Errores

```javascript
try {
    await enviarMensaje();
} catch (error) {
    if (error.response) {
        // Error de la API
        console.error('Status:', error.response.status);
        console.error('Datos:', error.response.data);
    } else if (error.request) {
        // No hubo respuesta
        console.error('Sin respuesta del servidor');
    } else {
        // Error en la configuración
        console.error('Error:', error.message);
    }
}
```

---

## 9. ESTRUCTURA DE DATOS

### 9.1 Sesión
```typescript
interface Session {
    sessionId: string;         // ID único de la sesión
    status: string;            // INITIAL | GENERATING_QR | CONNECTED | DISCONNECTED
    detail: string;            // Descripción del estado
    qr: string | null;         // Datos del código QR (solo si status === GENERATING_QR)
    token: string;             // Token de autenticación
    number: string;            // Número conectado (formato +123456789)
    owner: string;             // Email del dueño
    createdAt: number;         // Timestamp de creación
}
```

### 9.2 Mensaje
```typescript
interface Message {
    to: string;                // Número destino (sin + ni @s.whatsapp.net)
    text?: string;             // Texto del mensaje
    imageUrl?: string;         // URL de imagen
    documentUrl?: string;      // URL de documento
    fileName?: string;         // Nombre del archivo (para documentos)
}
```

### 9.3 Campaña
```typescript
interface Campaign {
    id: string;
    name: string;
    sessionId: string;
    message: string;           // Soporta variables: {{nombre}}, {{telefono}}, etc.
    recipients: Recipient[];
    delayBetweenMessages: number;  // Milisegundos
    delayBetweenBatches: number;   // Milisegundos
    status: 'draft' | 'running' | 'paused' | 'completed';
    progress: number;          // 0-100
}

interface Recipient {
    name: string;
    phone: string;
    [key: string]: any;        // Variables personalizadas
}
```

---

## 10. TROUBLESHOOTING

### Problema: El QR no se genera
- Verificar que el sessionId sea único
- Comprobar logs del servidor
- Reintentar con `DELETE /api/v1/sessions/:sessionId` y crear de nuevo

### Problema: "Invalid session token"
- El token puede haber expirado
- Verificar que el token sea el correcto
- Recrear la sesión si es necesario

### Problema: Mensajes no se envían
- Verificar que la sesión esté en estado `CONNECTED`
- Comprobar formato del número (solo dígitos, sin + ni espacios)
- Revisar límites de WhatsApp (evitar spam)

### Problema: Dashboard no carga
- Verificar `ADMIN_DASHBOARD_PASSWORD` en .env
- Revisar cookies del navegador
- Comprobar que el puerto esté accesible

---

## 11. ARCHIVOS CLAVE DEL PROYECTO

| Archivo | Líneas Clave | Responsabilidad |
|---------|--------------|------------------|
| `index.js` | 784-793, 565-593 | Servidor Express, conexión Baileys, generación QR, WebSocket |
| `api_v1.js` | - | Endpoints REST v1, autenticación, campañas |
| `admin/dashboard.html` | 817-821 | Panel web, renderización QR con qrcode.min.js |
| `users.js` | - | Sistema multiusuario, encriptación bcrypt |
| `campaigns.js` | - | Gestión de campañas de mensajes |
| `package.json` | - | v3.0.4 - Dependencias y scripts |

---

**Documentación generada automáticamente - Última actualización: 2025-12-27**
