# Callflow Visualizer - REST API Documentation

## Overview

The Callflow Visualizer provides a comprehensive REST API for asynchronous PCAP processing, session analysis, user authentication, and analytics.

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Content-Type**: `application/json`

## Authentication

The API supports two authentication methods:

### JWT Token Authentication

1. Login to obtain a JWT token
2. Include the token in the `Authorization` header: `Authorization: Bearer <token>`
3. Tokens expire after 24 hours (configurable)
4. Use the refresh endpoint to obtain a new access token

### API Key Authentication

1. Create an API key via the `/api/v1/auth/apikeys` endpoint
2. Include the key in the `X-API-Key` header: `X-API-Key: <api_key>`
3. API keys can have scoped permissions and expiry dates

### Public Endpoints (No Auth Required)

- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/register` - Register (if enabled)

---

## Health & Metrics Endpoints

### GET /health

Check if the API server is running.

**Response 200 (OK)**:
```json
{
  "status": "healthy",
  "timestamp": "2025-12-25T10:00:00.000Z",
  "version": "1.0.0"
}
```

### GET /metrics

Prometheus metrics endpoint (no authentication required).

**Response 200 (OK)**:
```
# HELP callflowd_jobs_total Total number of jobs by status
# TYPE callflowd_jobs_total counter
callflowd_jobs_total{status="completed"} 42
callflowd_jobs_total{status="failed"} 2
callflowd_jobs_total{status="running"} 1
callflowd_jobs_total{status="queued"} 0
# HELP callflowd_sessions_total Total sessions processed
# TYPE callflowd_sessions_total counter
callflowd_sessions_total 1250
# HELP callflowd_packets_total Total packets processed
# TYPE callflowd_packets_total counter
callflowd_packets_total 5000000
...
```

---

## Authentication Endpoints

### POST /api/v1/auth/register

Register a new user account.

**Request**:
```json
{
  "username": "user1",
  "password": "SecureP@ss123",
  "email": "user1@example.com"
}
```

**Response 201 (Created)**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "user1",
  "email": "user1@example.com",
  "roles": ["user"],
  "created_at": "2025-12-25T10:00:00.000Z"
}
```

**Response 400 (Bad Request)**:
```json
{
  "error": "Username already exists",
  "code": "USERNAME_EXISTS"
}
```

### POST /api/v1/auth/login

Login and obtain JWT tokens.

**Request**:
```json
{
  "username": "user1",
  "password": "SecureP@ss123"
}
```

**Response 200 (OK)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "user": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "user1",
    "roles": ["user"]
  }
}
```

**Response 401 (Unauthorized)**:
```json
{
  "error": "Invalid credentials",
  "code": "INVALID_CREDENTIALS"
}
```

### POST /api/v1/auth/refresh

Refresh an access token using a refresh token.

**Request**:
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response 200 (OK)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

### POST /api/v1/auth/logout

Logout and blacklist the current token.

**Headers**: `Authorization: Bearer <token>`

**Response 200 (OK)**:
```json
{
  "message": "Logged out successfully"
}
```

### GET /api/v1/auth/me

Get current user information.

**Headers**: `Authorization: Bearer <token>`

**Response 200 (OK)**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "user1",
  "email": "user1@example.com",
  "roles": ["user"],
  "created_at": "2025-12-25T10:00:00.000Z",
  "last_login": "2025-12-25T12:00:00.000Z"
}
```

### POST /api/v1/auth/change-password

Change the current user's password.

**Headers**: `Authorization: Bearer <token>`

**Request**:
```json
{
  "old_password": "OldP@ss123",
  "new_password": "NewSecureP@ss456"
}
```

**Response 200 (OK)**:
```json
{
  "message": "Password changed successfully"
}
```

### POST /api/v1/auth/apikeys

Create a new API key.

**Headers**: `Authorization: Bearer <token>`

**Request**:
```json
{
  "description": "CI/CD Pipeline Key",
  "scopes": ["jobs:read", "sessions:read"],
  "expires_in_days": 365
}
```

**Response 201 (Created)**:
```json
{
  "key_id": "660e8400-e29b-41d4-a716-446655440001",
  "api_key": "cfv_abc123xyz...",
  "description": "CI/CD Pipeline Key",
  "scopes": ["jobs:read", "sessions:read"],
  "created_at": "2025-12-25T10:00:00.000Z",
  "expires_at": "2026-12-25T10:00:00.000Z"
}
```

**Note**: The `api_key` is only shown once. Store it securely.

### GET /api/v1/auth/apikeys

List all API keys for the current user.

**Headers**: `Authorization: Bearer <token>`

**Response 200 (OK)**:
```json
{
  "api_keys": [
    {
      "key_id": "660e8400-e29b-41d4-a716-446655440001",
      "description": "CI/CD Pipeline Key",
      "scopes": ["jobs:read", "sessions:read"],
      "created_at": "2025-12-25T10:00:00.000Z",
      "expires_at": "2026-12-25T10:00:00.000Z",
      "last_used": "2025-12-25T14:00:00.000Z"
    }
  ]
}
```

### DELETE /api/v1/auth/apikeys/{key_id}

Revoke an API key.

**Headers**: `Authorization: Bearer <token>`

**Response 200 (OK)**:
```json
{
  "message": "API key revoked successfully"
}
```

---

## User Management Endpoints (Admin Only)

### GET /api/v1/users

List all users with pagination.

**Headers**: `Authorization: Bearer <admin_token>`

**Query Parameters**:
- `page` (integer, optional): Page number (default: 1)
- `limit` (integer, optional): Items per page (default: 50)

**Response 200 (OK)**:
```json
{
  "users": [
    {
      "user_id": "550e8400-e29b-41d4-a716-446655440000",
      "username": "admin",
      "email": "admin@example.com",
      "roles": ["admin"],
      "is_active": true,
      "created_at": "2025-12-25T10:00:00.000Z",
      "last_login": "2025-12-25T12:00:00.000Z"
    }
  ],
  "page": 1,
  "limit": 50,
  "total": 10
}
```

### POST /api/v1/users

Create a new user (admin only).

**Headers**: `Authorization: Bearer <admin_token>`

**Request**:
```json
{
  "username": "newuser",
  "password": "SecureP@ss123",
  "email": "newuser@example.com",
  "roles": ["user"]
}
```

**Response 201 (Created)**:
```json
{
  "user_id": "770e8400-e29b-41d4-a716-446655440002",
  "username": "newuser",
  "email": "newuser@example.com",
  "roles": ["user"],
  "created_at": "2025-12-25T10:00:00.000Z"
}
```

### PUT /api/v1/users/{user_id}

Update a user (admin only).

**Headers**: `Authorization: Bearer <admin_token>`

**Request**:
```json
{
  "email": "updated@example.com",
  "roles": ["user", "readonly"],
  "is_active": true
}
```

**Response 200 (OK)**:
```json
{
  "user_id": "770e8400-e29b-41d4-a716-446655440002",
  "username": "newuser",
  "email": "updated@example.com",
  "roles": ["user", "readonly"],
  "is_active": true
}
```

### DELETE /api/v1/users/{user_id}

Delete a user (admin only).

**Headers**: `Authorization: Bearer <admin_token>`

**Response 200 (OK)**:
```json
{
  "message": "User deleted successfully"
}
```

---

## Job Management Endpoints

### POST /api/v1/upload

Upload a PCAP file for processing.

**Headers**: `Authorization: Bearer <token>`

**Request**:
- Content-Type: `multipart/form-data`
- Body Parameters:
  - `file` (required): PCAP file (max 10GB)

**Response 201 (Created)**:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "created_at": "2025-12-25T10:00:00.000Z"
}
```

**Response 400 (Bad Request)**:
```json
{
  "error": "No file uploaded",
  "code": "NO_FILE"
}
```

**Response 413 (Payload Too Large)**:
```json
{
  "error": "File too large",
  "code": "FILE_TOO_LARGE",
  "max_size_mb": 10240
}
```

**Response 429 (Too Many Requests)**:
```json
{
  "error": "Rate limit exceeded",
  "code": "RATE_LIMIT_EXCEEDED",
  "retry_after": 60
}
```

**Example**:
```bash
curl -X POST http://localhost:8080/api/v1/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@capture.pcap"
```

### GET /api/v1/jobs

Get a list of all jobs.

**Headers**: `Authorization: Bearer <token>`

**Response 200 (OK)**:
```json
{
  "jobs": [
    {
      "job_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "completed",
      "progress": 100,
      "created_at": "2025-12-25T10:00:00.000Z",
      "completed_at": "2025-12-25T10:02:30.000Z",
      "session_count": 42,
      "total_packets": 125000,
      "total_bytes": 62500000
    },
    {
      "job_id": "660e8400-e29b-41d4-a716-446655440002",
      "status": "running",
      "progress": 45,
      "created_at": "2025-12-25T10:10:00.000Z"
    }
  ],
  "total": 2
}
```

### GET /api/v1/jobs/{job_id}/status

Get the status of a processing job.

**Headers**: `Authorization: Bearer <token>`

**Path Parameters**:
- `job_id` (string, required): Job ID from upload response

**Response 200 (OK)** - Queued:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "progress": 0,
  "created_at": "2025-12-25T10:00:00.000Z"
}
```

**Response 200 (OK)** - Running:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "progress": 45,
  "created_at": "2025-12-25T10:00:00.000Z",
  "started_at": "2025-12-25T10:00:05.000Z"
}
```

**Response 200 (OK)** - Completed:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "progress": 100,
  "created_at": "2025-12-25T10:00:00.000Z",
  "started_at": "2025-12-25T10:00:05.000Z",
  "completed_at": "2025-12-25T10:02:30.000Z",
  "total_packets": 125000,
  "total_bytes": 62500000,
  "session_count": 42
}
```

**Response 200 (OK)** - Failed:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "failed",
  "progress": 30,
  "created_at": "2025-12-25T10:00:00.000Z",
  "started_at": "2025-12-25T10:00:05.000Z",
  "completed_at": "2025-12-25T10:01:15.000Z",
  "error": "Failed to parse PCAP: invalid file format"
}
```

**Response 404 (Not Found)**:
```json
{
  "error": "Job not found",
  "code": "JOB_NOT_FOUND"
}
```

### GET /api/v1/jobs/{job_id}/sessions

Get sessions for a completed job (with pagination).

**Headers**: `Authorization: Bearer <token>`

**Path Parameters**:
- `job_id` (string, required): Job ID

**Query Parameters**:
- `page` (integer, optional): Page number (default: 1)
- `limit` (integer, optional): Items per page (default: 50)
- `type` (string, optional): Filter by session type (VoLTE, GTP, DIAMETER, etc.)

**Response 200 (OK)**:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "page": 1,
  "limit": 50,
  "total": 42,
  "sessions": [
    {
      "session_id": "660e8400-e29b-41d4-a716-446655440001",
      "type": "VoLTE",
      "session_key": "call-id-12345@192.168.1.1",
      "start_time": "2025-12-25T10:00:10.000Z",
      "end_time": "2025-12-25T10:05:30.000Z",
      "participants": ["192.168.1.1:5060", "192.168.1.2:5060"],
      "metrics": {
        "packets": 5234,
        "bytes": 1048576,
        "rtp_loss": 0.02,
        "rtp_jitter_ms": 3.5,
        "setup_time_ms": 450,
        "duration_ms": 320000
      },
      "events_count": 15
    }
  ]
}
```

**Response 400 (Bad Request)** - Job not completed:
```json
{
  "error": "Job not completed yet",
  "code": "JOB_NOT_COMPLETED",
  "current_status": "running"
}
```

### GET /api/v1/sessions/{session_id}

Get detailed information about a session.

**Headers**: `Authorization: Bearer <token>`

**Path Parameters**:
- `session_id` (string, required): Session ID

**Response 200 (OK)**:
```json
{
  "session_id": "660e8400-e29b-41d4-a716-446655440001",
  "type": "VoLTE",
  "session_key": "call-id-12345@192.168.1.1",
  "start_time": "2025-12-25T10:00:10.000Z",
  "end_time": "2025-12-25T10:05:30.000Z",
  "duration_ms": 320000,
  "packet_count": 5234,
  "byte_count": 1048576,
  "participants": ["192.168.1.1:5060", "192.168.1.2:5060"],
  "correlation_key": {
    "call_id": "call-id-12345@192.168.1.1",
    "imsi": "123456789012345"
  },
  "metrics": {
    "rtp_loss": 0.02,
    "rtp_jitter_ms": 3.5,
    "setup_time_ms": 450
  },
  "events": [
    {
      "event_id": "evt-001",
      "timestamp": "2025-12-25T10:00:10.000Z",
      "protocol": "SIP",
      "message_type": "INVITE",
      "source": "192.168.1.1:5060",
      "destination": "192.168.1.2:5060",
      "short": "SIP INVITE",
      "details": {
        "call_id": "call-id-12345@192.168.1.1",
        "from": "sip:alice@example.com",
        "to": "sip:bob@example.com",
        "cseq": "1 INVITE"
      }
    }
  ]
}
```

**Response 404 (Not Found)**:
```json
{
  "error": "Session not found",
  "code": "SESSION_NOT_FOUND"
}
```

### DELETE /api/v1/jobs/{job_id}

Delete a job and its results.

**Headers**: `Authorization: Bearer <token>`

**Path Parameters**:
- `job_id` (string, required): Job ID

**Response 200 (OK)**:
```json
{
  "message": "Job deleted successfully",
  "job_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response 400 (Bad Request)** - Job still running:
```json
{
  "error": "Job not found or still running",
  "code": "CANNOT_DELETE_JOB"
}
```

---

## Analytics Endpoints

### GET /api/v1/analytics/summary

Get overall statistics with optional date range filtering.

**Headers**: `Authorization: Bearer <token>`

**Query Parameters**:
- `start_date` (string, optional): Start date (ISO 8601 format)
- `end_date` (string, optional): End date (ISO 8601 format)

**Response 200 (OK)**:
```json
{
  "jobs": {
    "total": 45,
    "by_status": {
      "queued": 0,
      "running": 1,
      "completed": 42,
      "failed": 2
    }
  },
  "sessions": {
    "total": 1250,
    "by_type": {
      "VoLTE": 450,
      "GTP": 350,
      "DIAMETER": 250,
      "HTTP2": 150,
      "OTHER": 50
    }
  },
  "packets": {
    "total": 5000000,
    "total_bytes": 2500000000
  },
  "averages": {
    "session_duration_ms": 45000,
    "packets_per_session": 4000
  },
  "protocols": {
    "SIP": 15.5,
    "RTP": 45.2,
    "GTP": 18.3,
    "DIAMETER": 12.1,
    "HTTP2": 8.9
  },
  "cached": true,
  "cache_timestamp": "2025-12-25T10:00:00.000Z"
}
```

### GET /api/v1/analytics/protocols

Get protocol distribution and statistics.

**Headers**: `Authorization: Bearer <token>`

**Query Parameters**:
- `job_id` (string, optional): Filter by job ID

**Response 200 (OK)**:
```json
{
  "protocols": [
    {
      "protocol": "SIP",
      "session_count": 450,
      "packet_count": 125000,
      "byte_count": 50000000,
      "percentage": 15.5
    },
    {
      "protocol": "RTP",
      "session_count": 450,
      "packet_count": 2500000,
      "byte_count": 1500000000,
      "percentage": 45.2
    },
    {
      "protocol": "GTP",
      "session_count": 350,
      "packet_count": 750000,
      "byte_count": 400000000,
      "percentage": 18.3
    },
    {
      "protocol": "DIAMETER",
      "session_count": 250,
      "packet_count": 300000,
      "byte_count": 150000000,
      "percentage": 12.1
    },
    {
      "protocol": "HTTP2",
      "session_count": 150,
      "packet_count": 200000,
      "byte_count": 100000000,
      "percentage": 8.9
    }
  ]
}
```

### GET /api/v1/analytics/top-talkers

Get top IP addresses by traffic.

**Headers**: `Authorization: Bearer <token>`

**Query Parameters**:
- `limit` (integer, optional): Number of results (default: 10)
- `sort_by` (string, optional): Sort by "packets" or "bytes" (default: "packets")
- `job_id` (string, optional): Filter by job ID

**Response 200 (OK)**:
```json
{
  "top_talkers": [
    {
      "ip_address": "192.168.1.100",
      "session_count": 125,
      "packet_count": 500000,
      "byte_count": 250000000
    },
    {
      "ip_address": "10.0.0.50",
      "session_count": 98,
      "packet_count": 350000,
      "byte_count": 175000000
    }
  ],
  "limit": 10
}
```

### GET /api/v1/analytics/performance

Get system performance metrics.

**Headers**: `Authorization: Bearer <token>`

**Response 200 (OK)**:
```json
{
  "parsing": {
    "throughput_mbps": 250.5,
    "avg_job_completion_time_seconds": 45.2
  },
  "jobs": {
    "active": 1,
    "queued": 0
  },
  "api": {
    "total_requests": 15000,
    "avg_response_time_ms": 25.5
  },
  "system": {
    "memory_usage_mb": 512.5
  },
  "cache": {
    "hit_rate": 0.85
  }
}
```

### GET /api/v1/analytics/timeseries

Get time series data for charts.

**Headers**: `Authorization: Bearer <token>`

**Query Parameters**:
- `metric` (string, required): "jobs" or "sessions"
- `interval` (string, optional): "1h", "1d", "1w" (default: "1h")
- `start_date` (string, optional): Start date (ISO 8601)
- `end_date` (string, optional): End date (ISO 8601)

**Response 200 (OK)**:
```json
{
  "metric": "sessions",
  "interval": "1h",
  "data": [
    {
      "timestamp": "2025-12-25T00:00:00.000Z",
      "count": 45
    },
    {
      "timestamp": "2025-12-25T01:00:00.000Z",
      "count": 62
    },
    {
      "timestamp": "2025-12-25T02:00:00.000Z",
      "count": 38
    }
  ]
}
```

### POST /api/v1/analytics/cache/clear

Clear the analytics cache (admin only).

**Headers**: `Authorization: Bearer <admin_token>`

**Response 200 (OK)**:
```json
{
  "message": "Analytics cache cleared successfully"
}
```

---

## WebSocket Events

### WS /ws/jobs/{job_id}/events

Connect to receive real-time events for a job.

**Event Types**:

1. **Progress Event**:
```json
{
  "type": "progress",
  "timestamp": "2025-12-25T10:00:15.000Z",
  "data": {
    "packets": 10000,
    "bytes": 5000000,
    "progress": 25
  }
}
```

2. **Status Event**:
```json
{
  "type": "status",
  "timestamp": "2025-12-25T10:00:05.000Z",
  "data": {
    "status": "running"
  }
}
```

3. **Completion Event**:
```json
{
  "type": "completed",
  "timestamp": "2025-12-25T10:02:30.000Z",
  "data": {
    "status": "completed",
    "sessions": 42,
    "packets": 125000,
    "bytes": 62500000
  }
}
```

4. **Error Event**:
```json
{
  "type": "error",
  "timestamp": "2025-12-25T10:01:15.000Z",
  "data": {
    "error": "Failed to parse PCAP file"
  }
}
```

**Example** (using websocat):
```bash
websocat ws://localhost:8080/ws/jobs/550e8400-e29b-41d4-a716-446655440000/events
```

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `NO_FILE` | 400 | No file was uploaded |
| `FILE_TOO_LARGE` | 413 | Uploaded file exceeds size limit |
| `INVALID_FILE_TYPE` | 400 | Invalid file type (not PCAP/PCAPNG) |
| `JOB_NOT_FOUND` | 404 | Job ID not found |
| `JOB_NOT_COMPLETED` | 400 | Job hasn't completed yet |
| `SESSION_NOT_FOUND` | 404 | Session ID not found |
| `CANNOT_DELETE_JOB` | 400 | Cannot delete running job |
| `INVALID_CREDENTIALS` | 401 | Invalid username or password |
| `TOKEN_EXPIRED` | 401 | JWT token has expired |
| `TOKEN_INVALID` | 401 | JWT token is invalid |
| `UNAUTHORIZED` | 401 | Authentication required |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `USERNAME_EXISTS` | 400 | Username already registered |
| `EMAIL_EXISTS` | 400 | Email already registered |
| `WEAK_PASSWORD` | 400 | Password does not meet requirements |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Internal server error |

---

## Rate Limiting

The API implements token bucket rate limiting:

| Endpoint | Limit |
|----------|-------|
| Global | 60 requests/minute |
| `/api/v1/upload` | 5 requests/minute |
| `/api/v1/auth/login` | 10 requests/minute |
| Burst | 10 requests/10 seconds |

**Rate Limit Headers**:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1703502000
```

---

## CORS

CORS is configurable. Default settings:
- Allowed Origins: `*` (configure for production)
- Allowed Methods: `GET, POST, PUT, DELETE, OPTIONS`
- Allowed Headers: `Authorization, Content-Type, X-API-Key`

---

## Configuration

API server configuration can be set via:

### 1. Configuration File (`config.json`):
```json
{
  "server": {
    "bind_address": "0.0.0.0",
    "port": 8080,
    "workers": 4,
    "max_upload_size_mb": 10240
  },
  "auth": {
    "jwt_secret": "your-secret-key",
    "jwt_expiry_hours": 24,
    "refresh_token_expiry_days": 30,
    "allow_registration": true
  },
  "rate_limiting": {
    "requests_per_minute": 60,
    "burst_size": 10
  },
  "storage": {
    "upload_dir": "/data/uploads",
    "output_dir": "/data/results",
    "retention_hours": 24
  }
}
```

### 2. Environment Variables:
- `CALLFLOW_PORT`: API server port
- `CALLFLOW_BIND_ADDR`: Bind address
- `CALLFLOW_WORKERS`: Number of workers
- `CALLFLOW_JWT_SECRET`: JWT signing secret
- `CALLFLOW_UPLOAD_DIR`: Upload directory
- `CALLFLOW_RESULTS_DIR`: Results directory

### 3. Command Line:
```bash
./callflowd --api-server --api-port 8080 --api-bind 0.0.0.0 --config config.json
```

---

## Complete Workflow Example

```bash
# 1. Login to get a token
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"MySecureP@ss123"}' | jq -r '.access_token')

# 2. Upload PCAP file
RESPONSE=$(curl -X POST http://localhost:8080/api/v1/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@capture.pcap")
JOB_ID=$(echo $RESPONSE | jq -r '.job_id')
echo "Job ID: $JOB_ID"

# 3. Monitor progress
while true; do
  STATUS=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "http://localhost:8080/api/v1/jobs/$JOB_ID/status" | jq -r '.status')
  PROGRESS=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "http://localhost:8080/api/v1/jobs/$JOB_ID/status" | jq -r '.progress')
  echo "Status: $STATUS ($PROGRESS%)"
  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
    break
  fi
  sleep 2
done

# 4. Get sessions
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/jobs/$JOB_ID/sessions?page=1&limit=10" | jq

# 5. Get specific session detail
SESSION_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/jobs/$JOB_ID/sessions" | jq -r '.sessions[0].session_id')
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/sessions/$SESSION_ID" | jq

# 6. Get analytics
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/analytics/summary" | jq

# 7. Get Prometheus metrics (no auth required)
curl -s http://localhost:8080/metrics
```

---

## Prometheus Metrics

The `/metrics` endpoint exports the following metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `callflowd_jobs_total{status}` | Counter | Total jobs by status |
| `callflowd_sessions_total` | Counter | Total sessions processed |
| `callflowd_sessions_by_protocol{protocol}` | Counter | Sessions per protocol |
| `callflowd_packets_total` | Counter | Total packets processed |
| `callflowd_bytes_total` | Counter | Total bytes processed |
| `callflowd_parsing_throughput_mbps` | Gauge | Current parsing throughput |
| `callflowd_job_completion_time_seconds` | Gauge | Average job completion time |
| `callflowd_active_jobs` | Gauge | Currently active jobs |
| `callflowd_queued_jobs` | Gauge | Jobs in queue |
| `callflowd_memory_usage_bytes` | Gauge | Process memory usage |
| `callflowd_api_requests_total` | Counter | Total API requests |
| `callflowd_api_response_time_milliseconds` | Gauge | Average API response time |
| `callflowd_session_duration_milliseconds` | Gauge | Average session duration |
| `callflowd_packets_per_session` | Gauge | Average packets per session |
