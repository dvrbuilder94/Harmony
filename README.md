# SalesHarmony 🚀

Sistema de gestión de ventas multiusuario con autenticación JWT y arquitectura Flask + React.

## 🏗️ Arquitectura

- **Backend**: Flask + SQLAlchemy + JWT Authentication
- **Frontend**: React + TypeScript + Vite + Tailwind CSS
- **Base de datos**: PostgreSQL (producción) / SQLite (desarrollo)
- **Autenticación**: JWT con roles multiusuario
- **Despliegue**: Replit con Gunicorn

## 🚦 Inicio Rápido

### Prerrequisitos

- Python 3.11+
- Node.js 20+
- PostgreSQL (opcional, usa SQLite por defecto)

### 1. Configuración del Backend

```bash
# Clonar repositorio
git clone <tu-repo-url>
cd salesharmony

# Crear archivo de entorno
cp .env.example .env
# Editar .env con tus valores

# Instalar dependencias
pip install -r requirements.txt

# Inicializar base de datos (SQLite por defecto)
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

### 2. Configuración del Frontend

```bash
# Navegar al directorio frontend
cd frontend

# Instalar dependencias
npm install

# Ejecutar en modo desarrollo
npm run dev
```

### 3. Ejecutar la Aplicación

**Opción 1: Desarrollo separado**
```bash
# Terminal 1 - Backend
gunicorn --bind 0.0.0.0:5000 app:app --reload

# Terminal 2 - Frontend
cd frontend && npm run dev
```

**Opción 2: Producción**
```bash
# Construir frontend
cd frontend && npm run build

# Servir todo desde Flask
gunicorn --bind 0.0.0.0:5000 app:app
```

## 🔐 Sistema de Autenticación

### Usuarios de Prueba (Solo Desarrollo)

⚠️ **IMPORTANTE**: Para seguridad, no se crean usuarios automáticamente en producción.

Para habilitar usuarios de prueba en desarrollo local:
```bash
# En tu archivo .env
FLASK_ENV=development
SEED_TEST_USERS=true
```

Esto creará usuarios de prueba que podrás usar para testing y desarrollo.

### Endpoints de Autenticación

- `POST /auth/login` - Login de usuario
- `POST /auth/register` - Registro de usuario (rol: user)
- `GET /auth/me` - Información del usuario actual

## 📊 Funcionalidades Principales

- ✅ **Autenticación JWT multiusuario**
- ✅ **Dashboard con métricas en tiempo real**
- ✅ **Sistema de roles (admin/user)**
- ✅ **Gestión de ventas y conciliación**
- ✅ **API RESTful documentada**
- ✅ **Interfaz responsiva con Tailwind**

## 🗂️ Estructura del Proyecto

```
salesharmony/
├── app.py                 # Aplicación Flask principal
├── models.py              # Modelos de base de datos
├── requirements.txt       # Dependencias Python
├── pyproject.toml         # Proyecto Python (opcional)
├── frontend/              # Aplicación React
│   ├── src/
│   │   ├── components/   # Componentes reutilizables
│   │   ├── pages/        # Páginas principales
│   │   ├── stores/       # Estado global (Zustand)
│   │   ├── services/     # Servicios API
│   │   └── types/        # Tipos TypeScript
│   ├── package.json
│   └── vite.config.ts
├── static/               # Archivos estáticos
├── templates/            # Templates HTML
└── tests/               # Tests
```

## 🔧 Variables de Entorno

| Variable | Descripción | Ejemplo |
|----------|-------------|---------|
| `SESSION_SECRET` | Clave secreta Flask/JWT | `tu_clave_super_secreta` |
| `DATABASE_URL` | URL de base de datos | `sqlite:///salesharmony.db` |
| `FLASK_ENV` | Entorno de Flask | `development` |
| `VITE_API_URL` | URL de API para frontend | `http://localhost:5000` |

## 🧪 Testing

```bash
# Ejecutar tests
pytest

# Con cobertura
pytest --cov=. --cov-report=html
```

## 🚀 Despliegue

### Replit
1. Fork el proyecto en Replit
2. Configurar variables de entorno en Secrets
3. Ejecutar con el comando: `gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app`

### Heroku
```bash
# Crear app
heroku create tu-app-name

# Configurar variables
heroku config:set SESSION_SECRET=tu_clave_secreta
heroku config:set DATABASE_URL=postgresql://...

# Deploy
git push heroku main
```

## 🤝 Contribución

1. Fork el proyecto
2. Crear feature branch (`git checkout -b feature/nueva-funcionalidad`)
3. Commit cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push al branch (`git push origin feature/nueva-funcionalidad`)
5. Crear Pull Request

## 📝 API Documentation

### Endpoints Principales

#### Autenticación
- `POST /auth/login` - Login
- `POST /auth/register` - Registro
- `GET /auth/me` - Usuario actual

#### Ventas
- `GET /api/sales` - Listado paginado (JWT)
- `POST /api/sales` - Crear venta (JWT)

#### Estado del Sistema
- `GET /health` - Estado de salud del sistema

## 🛠️ Troubleshooting

### Problemas Comunes

**Error de conexión backend ↔ frontend**
```bash
# Verificar que el backend esté ejecutando en puerto 5000
curl http://localhost:5000/health

# Verificar configuración VITE_API_URL
echo $VITE_API_URL
```

**Base de datos no inicializada**
```bash
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

**Problemas de autenticación**
- Verificar `SESSION_SECRET` en .env
- Limpiar localStorage del navegador
- Verificar formato del token JWT

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver `LICENSE` para más detalles.

## 👥 Autores

- **Tu Nombre** - Desarrollo inicial

---

⭐ Si este proyecto te ayuda, ¡dale una estrella en GitHub!