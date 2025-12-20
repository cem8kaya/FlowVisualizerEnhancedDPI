# Callflow Visualizer - REST API Documentation

## Overview

The Callflow Visualizer provides a REST API for asynchronous PCAP processing and result retrieval.

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Content-Type**: `application/json`

## Authentication

Currently, no authentication is required. This will be added in future versions.

## Endpoints

### Health Check

#### GET /health

Check if the API server is running.

**Response 200 (OK)**:
```json
{
  "status": "healthy",
  "timestamp": "2025-11-13T10:00:00.000Z"
}
```

---

### Upload PCAP File

#### POST /api/v1/upload

Upload a PCAP file for processing.

**Request**:
- Content-Type: `multipart/form-data`
- Body Parameters:
  - `file` (required): PCAP file (max 10GB)

**Response 201 (Created)**:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued"
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

**Example**:
```bash
curl -X POST http://localhost:8080/api/v1/upload \
  -F "file=@capture.pcap"
```

---

### Get Job Status

#### GET /api/v1/jobs/{job_id}/status

Get the status of a processing job.

**Path Parameters**:
- `job_id` (string, required): Job ID from upload response

**Response 200 (OK)** - Queued:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "progress": 0,
  "created_at": "2025-11-13T10:00:00.000Z"
}
```

**Response 200 (OK)** - Running:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "progress": 45,
  "created_at": "2025-11-13T10:00:00.000Z",
  "started_at": "2025-11-13T10:00:05.000Z"
}
```

**Response 200 (OK)** - Completed:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "progress": 100,
  "created_at": "2025-11-13T10:00:00.000Z",
  "started_at": "2025-11-13T10:00:05.000Z",
  "completed_at": "2025-11-13T10:02:30.000Z",
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
  "created_at": "2025-11-13T10:00:00.000Z",
  "started_at": "2025-11-13T10:00:05.000Z",
  "completed_at": "2025-11-13T10:01:15.000Z",
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

---

### Get Job Sessions

#### GET /api/v1/jobs/{job_id}/sessions

Get sessions for a completed job (with pagination).

**Path Parameters**:
- `job_id` (string, required): Job ID

**Query Parameters**:
- `page` (integer, optional): Page number (default: 1)
- `limit` (integer, optional): Items per page (default: 50)

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
      "start_time": "2025-11-13T10:00:10.000Z",
      "end_time": "2025-11-13T10:05:30.000Z",
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

---

### Get Session Detail

#### GET /api/v1/sessions/{session_id}

Get detailed information about a session.

**Path Parameters**:
- `session_id` (string, required): Session ID

**Response 200 (OK)**:
```json
{
  "session_id": "660e8400-e29b-41d4-a716-446655440001",
  "type": "VoLTE",
  "session_key": "call-id-12345@192.168.1.1",
  "start_time": "2025-11-13T10:00:10.000Z",
  "end_time": "2025-11-13T10:05:30.000Z",
  "duration_ms": 320000,
  "packet_count": 5234,
  "byte_count": 1048576,
  "participants": ["192.168.1.1:5060", "192.168.1.2:5060"],
  "metrics": {
    "rtp_loss": 0.02,
    "rtp_jitter_ms": 3.5,
    "setup_time_ms": 450
  },
  "events": [
    {
      "event_id": "evt-001",
      "timestamp": "2025-11-13T10:00:10.000Z",
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

---

### Get All Jobs

#### GET /api/v1/jobs

Get a list of all jobs.

**Response 200 (OK)**:
```json
{
  "jobs": [
    {
      "job_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "completed",
      "progress": 100,
      "created_at": "2025-11-13T10:00:00.000Z",
      "session_count": 42,
      "total_packets": 125000
    },
    {
      "job_id": "660e8400-e29b-41d4-a716-446655440002",
      "status": "running",
      "progress": 45,
      "created_at": "2025-11-13T10:10:00.000Z"
    }
  ],
  "total": 2
}
```

---

### Delete Job

#### DELETE /api/v1/jobs/{job_id}

Delete a job and its results.

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

## WebSocket Events

### WS /ws/jobs/{job_id}/events

Connect to receive real-time events for a job.

**Event Types**:

1. **Progress Event**:
```json
{
  "type": "progress",
  "timestamp": "2025-11-13T10:00:15.000Z",
  "data": {
    "packets": 10000,
    "bytes": 5000000
  }
}
```

2. **Status Event**:
```json
{
  "type": "status",
  "timestamp": "2025-11-13T10:00:05.000Z",
  "data": {
    "status": "running"
  }
}
```

3. **Completion Event**:
```json
{
  "type": "status",
  "timestamp": "2025-11-13T10:02:30.000Z",
  "data": {
    "status": "completed",
    "sessions": 42,
    "packets": 125000,
    "bytes": 62500000
  }
}
```

**Example** (using websocat):
```bash
websocat ws://localhost:8080/ws/jobs/550e8400-e29b-41d4-a716-446655440000/events
```

---

## Error Codes

| Code | Description |
|------|-------------|
| `NO_FILE` | No file was uploaded |
| `FILE_TOO_LARGE` | Uploaded file exceeds size limit |
| `JOB_NOT_FOUND` | Job ID not found |
| `JOB_NOT_COMPLETED` | Job hasn't completed yet |
| `SESSION_NOT_FOUND` | Session ID not found |
| `CANNOT_DELETE_JOB` | Cannot delete running job |
| `INTERNAL_ERROR` | Internal server error |

---

## Rate Limiting

Currently, no rate limiting is implemented. This will be added in future versions.

---

## CORS

CORS is enabled for all origins (`*`). This can be configured in production.

---

## Configuration

API server configuration can be set via:

1. **Configuration File** (`--config config.json`):
```json
{
  "server": {
    "bind_address": "0.0.0.0",
    "port": 8080,
    "workers": 4,
    "max_upload_size_mb": 10240
  },
  "storage": {
    "upload_dir": "/tmp/callflow-uploads",
    "output_dir": "/tmp/callflow-results",
    "retention_hours": 24
  }
}
```

2. **Environment Variables**:
- `CALLFLOW_PORT`: API server port
- `CALLFLOW_BIND_ADDR`: Bind address
- `CALLFLOW_WORKERS`: Number of workers
- `CALLFLOW_UPLOAD_DIR`: Upload directory
- `CALLFLOW_RESULTS_DIR`: Results directory

3. **Command Line**:
```bash
./callflowd --api-server --api-port 8080 --api-bind 0.0.0.0
```

---

## Complete Workflow Example

```bash
# 1. Upload PCAP file
RESPONSE=$(curl -X POST http://localhost:8080/api/v1/upload \
  -F "file=@capture.pcap")
JOB_ID=$(echo $RESPONSE | jq -r '.job_id')

# 2. Monitor progress
while true; do
  STATUS=$(curl -s "http://localhost:8080/api/v1/jobs/$JOB_ID/status" | jq -r '.status')
  if [ "$STATUS" = "completed" ]; then
    break
  fi
  sleep 2
done

# 3. Get sessions
curl "http://localhost:8080/api/v1/jobs/$JOB_ID/sessions?page=1&limit=10"

# 4. Get specific session detail
SESSION_ID=$(curl -s "http://localhost:8080/api/v1/jobs/$JOB_ID/sessions" | jq -r '.sessions[0].session_id')
curl "http://localhost:8080/api/v1/sessions/$SESSION_ID"
```

---

## Future Enhancements (M3+)

- Authentication (JWT tokens)
- Rate limiting
- WebSocket authentication
- Packet detail endpoint (`GET /api/v1/packets/{packet_id}`)
- Live capture support
- Filtering and search
- Export formats (CSV, Wireshark)
