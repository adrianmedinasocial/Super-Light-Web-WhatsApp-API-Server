# 🚂 Fix para Railway - Express Rate Limit Error

## Problema

Si estás viendo este error en los logs de Railway:

```
ValidationError: The Express 'trust proxy' setting is true, which allows anyone
to trivially bypass IP-based rate limiting.
```

## Causa

La versión 7.x de `express-rate-limit` introdujo validaciones de seguridad más estrictas. El problema ocurre cuando:

1. `app.set('trust proxy', true)` está configurado (permitir cualquier proxy)
2. `trustProxy: true` está en el rate limiter
3. Esto permite que usuarios maliciosos falsifiquen su IP y eviten el rate limiting

## Solución Aplicada ✅

### Archivos modificados:

#### 1. `index.js` (línea 166)
```javascript
// ANTES:
app.set('trust proxy', true);

// DESPUÉS:
app.set('trust proxy', 1); // Solo confía en el primer proxy (Railway)
```

#### 2. `index.js` (línea 187)
```javascript
// ANTES:
trustProxy: true,

// DESPUÉS:
trustProxy: false, // Usa la configuración global de app.set('trust proxy')
```

#### 3. `api_v1.js` (línea 46)
```javascript
// ANTES:
trustProxy: true,

// DESPUÉS:
trustProxy: false, // Usa la configuración global de app.set('trust proxy')
```

#### 4. `legacy_api.js` (línea 29)
```javascript
// ANTES:
trustProxy: true,

// DESPUÉS:
trustProxy: false, // Usa la configuración global de app.set('trust proxy')
```

## ¿Por qué funciona?

- **Railway** usa un único reverse proxy (nginx) frente a tu aplicación
- Al configurar `trust proxy: 1`, le decimos a Express que confíe solo en el primer proxy (Railway)
- Al poner `trustProxy: false` en los rate limiters, heredan la configuración global de Express
- Esto es más seguro que `trust proxy: true` que confía en cualquier proxy

## Deployment en Railway

Después de aplicar estos cambios:

1. Hacer commit de los cambios:
```bash
git add .
git commit -m "Fix: Configurar trust proxy para Railway correctamente"
git push
```

2. Railway detectará automáticamente los cambios y redesplegará

3. Verificar en los logs que el error ya no aparece

## Otros Deployments

### Vercel / Netlify
Igual que Railway, usan 1 proxy:
```javascript
app.set('trust proxy', 1);
```

### Render
Igual que Railway:
```javascript
app.set('trust proxy', 1);
```

### Heroku
Heroku puede usar múltiples proxies:
```javascript
app.set('trust proxy', 1); // Prueba con 1 primero, si no funciona intenta 2
```

### cPanel / Servidor propio con nginx
Si conoces la IP de tu proxy:
```javascript
app.set('trust proxy', '127.0.0.1'); // Solo localhost
```

### Multiple proxies (Cloudflare + nginx)
```javascript
app.set('trust proxy', 2); // Cloudflare + nginx = 2 proxies
```

## Verificación

Para verificar que funciona correctamente:

1. Revisa los logs de Railway - el error debe desaparecer
2. Los webhooks deben funcionar correctamente
3. El rate limiting sigue activo (100 requests/min)

## Referencias

- [Express Rate Limit - Trust Proxy Error](https://express-rate-limit.github.io/ERR_ERL_PERMISSIVE_TRUST_PROXY/)
- [Express Trust Proxy Documentation](https://expressjs.com/en/guide/behind-proxies.html)
- [Railway Proxy Configuration](https://docs.railway.app/)

---

**Fecha de fix:** 2025-12-27
**Versión:** 3.0.4
