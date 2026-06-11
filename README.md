# Blockchain Auditor — Hyperledger Fabric

Sistema de auditoría que captura eventos del sistema operativo y los almacena
de forma inmutable en una blockchain de Hyperledger Fabric.

## Arquitectura

```
┌──────────────┐     HTTP POST /api/events      ┌───────────┐    gRPC     ┌───────────┐
│  C Auditor   │ ───────────────────────────►   │  Gateway  │ ──────────► │  Fabric   │
│  (ptrace)    │                                │  (Node)   │             │  Peer     │
│              │ ◄───────────────────────────   │  :8443    │ ◄────────── │  :7051    │
└──────────────┘        GET /api/verify         └───────────┘             └───────────┘
       │                                                                        │
       ▼                                                                        ▼
      log/                                                                  Chaincode
```

## Requisitos del Sistema

### Herramientas de desarrollo

| Paquete      | Versión mínima | Propósito                                 |
| ------------ | -------------- | ----------------------------------------- |
| `gcc`        | 8+             | Compilador de C                           |
| `make`       | 4+             | Sistema de build                          |
| `OpenSSL`    | 1.1+           | Hashing SHA-256                           |
| `libcurl`    | 7+             | Cliente HTTP                              |
| `pkg-config` | —              | Detectar librerías del sistema            |
| `auditd`     | opcional       | Monitoreo con Linux Audit (requiere root) |

### Entorno de ejecución

| Paquete            | Versión | Propósito                |
| ------------------ | ------- | ------------------------ |
| **Docker**         | 24+     | Contenedores de Fabric   |
| **Docker Compose** | 2.20+   | Orquestar contenedores   |
| **Node.js**        | 18+     | Gateway REST y chaincode |
| **npm**            | 9+      | Gestor de paquetes JS    |

### Puertos utilizados

| Puerto | Servicio          |
| ------ | ----------------- |
| `7050` | Orderer (gRPC)    |
| `7051` | Peer (gRPC)       |
| `7052` | Peer (chaincode)  |
| `8443` | Gateway REST API  |
| `9443` | Orderer admin API |

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/CristianL15/blockchainOS blockchainOS
cd blockchainOS
```

### 2. Instalar dependencias del sistema (Fedora/RHEL)

```bash
sudo dnf install gcc make openssl-devel libcurl-devel pkg-config
# Opcional: soporte para Linux Audit
sudo dnf install audit-libs-devel
```

### 3. Descargar imágenes de Hyperledger Fabric

```bash
cd fabric
./network.sh pull
cd ..
```

### 4. Compilar el binario C e instalar módulos Node.js

```bash
make full
```

Esto ejecuta:

- `make` → compila el binario `auditor`
- `make gateway` → `npm install` en `gateway/`
- `make chaincode` → `npm install` en `chaincode/`

## Ejecución

###

```bash
./start.sh
```

Esto:

1. Compila el binario C (si no está actualizado)
2. Genera material criptográfico y levanta los contenedores de Fabric
3. Crea el canal `auditchannel`
4. Instala y activa el chaincode
5. Inicia el gateway REST en el puerto `8443`

### Detener todo

```bash
./stop.sh
```

## Uso

### Capturar un comando

```bash
# Con gateway (envía a la blockchain)
./auditor run ls -la

# Solo local (sin gateway)
./auditor run --local-only ls -la
```

### Consultar eventos desde la blockchain

```bash
# Estado del sistema
curl -s http://localhost:8443/api/status

# Listar todos los eventos
curl -s http://localhost:8443/api/events | jq

# Buscar por hash
curl -s http://localhost:8443/api/events/<hash>

# Verificar integridad (recalcula hashes)
curl -s http://localhost:8443/api/verify
```

### Otros modos del auditor

```bash
# Verificar integridad desde el gateway
./auditor verify

# Benchmark de rendimiento (10 ejecuciones)
./auditor benchmark ls

# Prueba de estrés (10 procesos concurrentes)
./auditor stress -c 10

# Prueba de detección de manipulación
./auditor integrity-test

# Limpiar logs locales
./auditor clear
```

### Modo daemon

```bash
# Iniciar daemon en primer plano (sondeo /proc)
./auditor daemon

# Iniciar con Linux Audit (requiere root)
sudo ./auditor daemon --audit

# Iniciar como daemon de fondo
./auditor daemon --daemon

# Detener el daemon
./auditor daemon stop

# Ver estado del daemon
./auditor daemon status
```
