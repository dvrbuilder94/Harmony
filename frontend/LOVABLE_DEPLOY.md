Lovable - Deploy del frontend (MVP)

Objetivo: Publicar el frontend con modo mock para demo inmediata. Luego podrás apuntarlo al backend real sin cambiar código.

1) Configuración del proyecto
- Working directory: frontend
- Build command: npm install && npm run build
- Output directory: dist

2) Variables de entorno (Environment Variables)
- VITE_MOCK=true  (MVP sin backend)
- VITE_API_URL=   (dejar vacío por ahora; luego usar https://TU_BACKEND.onrender.com)

3) Despliegue
- Ejecuta el deploy en Lovable con la configuración anterior.
- Al finalizar, obtendrás una URL pública del frontend (https://tu-sitio.lovable.app/...)

4) Prueba rápida
- Abre la URL pública
- Inicia sesión con cualquier email/password (mock devuelve token)
- Pulsa “Conectar Mercado Libre” (abre un mock) y luego “Sincronizar Órdenes” (verás JSON mock de órdenes)

5) Conectar al backend real (cuando esté listo)
- Cambia variables en Lovable y redeploy:
  - VITE_MOCK=false
  - VITE_API_URL=https://TU_BACKEND.onrender.com
- En el backend (Render), define ALLOWED_ORIGINS con la URL pública de Lovable

Notas
- Tailwind 4 está configurado con postcss.config.js para builds consistentes.
- Si necesitas múltiples orígenes en CORS, sepáralos por comas en ALLOWED_ORIGINS.
