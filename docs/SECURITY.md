# Security Documentation

## Overview

This document describes the security features, best practices, and threat model for the nDPI Callflow Visualizer (Milestone 5: Production Hardening).

## Security Features

### 1. Input Validation

All user inputs are validated and sanitized to prevent common vulnerabilities:

#### File Upload Validation

- **File Type**: Only `.pcap`, `.pcapng`, and `.cap` files accepted
- **Magic Number Check**: Validates PCAP file format
- **Size Limits**: Maximum 10GB per upload
- **Path Traversal**: Blocks `../` and similar sequences
- **Filename Sanitization**: Removes special characters

#### API Input Validation

- **Username**: 1-50 alphanumeric characters, underscore, hyphen, dot
- **Email**: RFC 5322 compliant email format
- **Password**: 8-128 characters with complexity requirements
- **Job/Session IDs**: Alphanumeric with hyphens only
- **Pagination**: Page ≥ 0, Limit 1-1000

### 2. Rate Limiting

Protection against DoS and brute-force attacks:

- **Global Limit**: 60 requests/minute per client IP
- **Burst Protection**: Max 10 requests per 10 seconds
- **Per-Endpoint Limits**:
  - Upload: 5 req/min
  - Login: 10 req/min
  - Registration: 5 req/min

Rate limit headers in responses:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 42
```

### 3. Authentication & Authorization

#### JWT-Based Authentication

- **Algorithm**: HS256 (HMAC with SHA-256)
- **Token Expiry**: 24 hours (configurable)
- **Refresh Tokens**: 30 days (configurable)
- **Secret Key**: Configurable via environment variable

**Security Recommendations:**
- Use strong, random JWT secret (minimum 256 bits)
- Rotate secrets periodically
- Store secrets in environment variables or secret management systems
- Never commit secrets to version control

#### Password Security

- **Hashing**: bcrypt with configurable rounds (default: 12)
- **Policy**:
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one digit
  - Optional: Special characters

#### Role-Based Access Control (RBAC)

Three built-in roles:

1. **admin**: Full access to all endpoints
2. **user**: Can upload files, view own jobs, create sessions
3. **readonly**: Can only view data

### 4. API Key Support

For programmatic access:

- **Format**: `cfv_<random_32_chars>`
- **Storage**: SHA-256 hash in database
- **Scopes**: read, write, admin
- **Expiry**: Configurable (default: 365 days)
- **Revocation**: Can be revoked at any time

### 5. TLS/HTTPS Support

- **Protocols**: TLS 1.2, TLS 1.3
- **Ciphers**: Modern, secure cipher suites
- **Certificate Management**: Support for custom certificates
- **HTTP Redirect**: Optional automatic HTTPS redirect

### 6. Database Security

#### SQL Injection Prevention

- **Prepared Statements**: All queries use parameterized statements
- **Input Validation**: Additional validation before database operations
- **Principle of Least Privilege**: Database user has minimal permissions

#### Data Protection

- **Encryption at Rest**: Use encrypted volumes for database files
- **Backups**: Regular automated backups with encryption
- **Retention Policy**: Automatic cleanup of old data (configurable)

### 7. Security Headers

All HTTP responses include security headers:

```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### 8. CORS Policy

Configurable CORS policy:

```json
{
  "security": {
    "enable_cors": true,
    "allowed_origins": ["https://example.com"],
    "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
    "allowed_headers": ["Content-Type", "Authorization"]
  }
}
```

### 9. Audit Logging

All security-relevant events are logged:

- Authentication attempts (success/failure)
- Authorization failures
- API key usage
- Configuration changes
- Administrative actions
- Suspicious activity

Log format:
```
[timestamp] [level] [user] [action] [result] [details]
```

## Threat Model

### Assets

1. **PCAP Files**: Uploaded network captures (may contain sensitive data)
2. **Database**: User credentials, session data, analytics
3. **Configuration**: API keys, JWT secrets, TLS certificates
4. **Application**: Server availability and integrity

### Threats

#### 1. Unauthorized Access

**Threat**: Attackers gain access to protected resources

**Mitigations**:
- JWT authentication required for all protected endpoints
- Strong password policy enforced
- Rate limiting on authentication endpoints
- Account lockout after failed attempts
- Session timeout

#### 2. Data Exposure

**Threat**: Sensitive data leaked through API or database

**Mitigations**:
- TLS encryption for data in transit
- Database encryption at rest
- Sanitization of error messages
- No sensitive data in logs
- Secure file upload handling

#### 3. Injection Attacks

**Threat**: SQL injection, XSS, command injection

**Mitigations**:
- Prepared statements for all database queries
- Input validation and sanitization
- Output encoding
- No eval() or dynamic code execution
- Path traversal prevention

#### 4. Denial of Service

**Threat**: Service disruption through resource exhaustion

**Mitigations**:
- Rate limiting per client
- Request size limits
- Connection limits
- Timeout configurations
- Resource quotas

#### 5. Privilege Escalation

**Threat**: Users gain elevated privileges

**Mitigations**:
- RBAC with role validation
- Token-based authorization
- No privilege elevation in API
- Audit logging of privilege changes

#### 6. Man-in-the-Middle

**Threat**: Eavesdropping on communications

**Mitigations**:
- TLS 1.2+ encryption
- Certificate validation
- HSTS headers
- Secure cookie flags

## Security Best Practices

### Deployment

1. **Use HTTPS in Production**
   ```bash
   # Generate production certificates with Let's Encrypt
   certbot certonly --standalone -d your-domain.com
   ```

2. **Secure JWT Secret**
   ```bash
   # Generate strong secret
   openssl rand -hex 32

   # Set as environment variable
   export JWT_SECRET="<generated-secret>"
   ```

3. **Run as Non-Root**
   - Docker container runs as UID 1000 by default
   - Kubernetes security context enforces non-root

4. **Network Isolation**
   ```yaml
   # Kubernetes NetworkPolicy
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: callflowd-policy
   spec:
     podSelector:
       matchLabels:
         app: callflowd
     policyTypes:
     - Ingress
     ingress:
     - from:
       - podSelector:
           matchLabels:
             role: frontend
   ```

5. **Regular Updates**
   ```bash
   # Update base image
   docker pull ubuntu:24.04
   docker build --no-cache -t callflowd:latest .
   ```

### Configuration

1. **Disable Registration in Production**
   ```json
   {
     "auth": {
       "allow_registration": false
     }
   }
   ```

2. **Restrict CORS Origins**
   ```json
   {
     "security": {
       "allowed_origins": ["https://your-domain.com"]
     }
   }
   ```

3. **Enable Audit Logging**
   ```json
   {
     "security": {
       "enable_audit_log": true,
       "audit_log_path": "/app/logs/audit.log"
     }
   }
   ```

4. **Set Strong Password Policy**
   ```json
   {
     "security": {
       "password_policy": {
         "min_length": 12,
         "require_uppercase": true,
         "require_lowercase": true,
         "require_digits": true,
         "require_special_chars": true
       }
     }
   }
   ```

### Monitoring

1. **Enable Prometheus Metrics**
   - Monitor authentication failures
   - Track rate limit violations
   - Watch for unusual patterns

2. **Set Up Alerts**
   ```yaml
   # Prometheus alert rules
   - alert: HighAuthFailureRate
     expr: rate(auth_failures_total[5m]) > 10
     annotations:
       summary: "High authentication failure rate detected"
   ```

3. **Log Analysis**
   ```bash
   # Monitor failed login attempts
   grep "AUTH_FAILED" /app/logs/audit.log | tail -100

   # Check rate limit violations
   grep "RATE_LIMIT_EXCEEDED" /app/logs/callflowd.log
   ```

## Vulnerability Reporting

### Responsible Disclosure

If you discover a security vulnerability:

1. **DO NOT** create a public GitHub issue
2. Email security@example.com with details
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### Response Timeline

- **Initial Response**: Within 24 hours
- **Vulnerability Assessment**: Within 7 days
- **Fix Development**: Based on severity
- **Patch Release**: Based on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: Next release

### CVE Assignment

Critical vulnerabilities will be assigned CVE numbers and publicly disclosed after patch release.

## Security Testing

### Automated Scanning

CI/CD pipeline includes:

1. **Trivy**: Container vulnerability scanning
2. **CodeQL**: Static application security testing (SAST)
3. **Dependency Scanning**: Third-party library vulnerabilities

### Manual Testing

Periodic security assessments:

1. **Penetration Testing**: Annual external pentest
2. **Code Review**: Security-focused code reviews
3. **Threat Modeling**: Regular threat model updates

### Tools

Recommended security testing tools:

```bash
# OWASP ZAP for web application scanning
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://localhost:8080

# Nmap for port scanning
nmap -sV -sC localhost

# SQLMap for SQL injection testing
sqlmap -u "http://localhost:8080/api/v1/jobs?id=1"
```

## Compliance

### Data Protection

- **GDPR**: Supports data deletion and export
- **Data Retention**: Configurable retention policies
- **Audit Trail**: Complete audit log of data access

### Industry Standards

- **OWASP Top 10**: Mitigations implemented
- **CWE Top 25**: Common weaknesses addressed
- **NIST Cybersecurity Framework**: Aligns with CSF

## Incident Response

### Detection

1. Monitor audit logs for suspicious activity
2. Set up alerts for anomalies
3. Regular log review

### Response

1. **Identify**: Determine scope and impact
2. **Contain**: Isolate affected systems
3. **Eradicate**: Remove threat
4. **Recover**: Restore normal operations
5. **Lessons Learned**: Update security measures

### Contact

Security incidents: security@example.com

## Security Checklist

### Pre-Deployment

- [ ] Generate strong JWT secret
- [ ] Configure TLS certificates
- [ ] Disable public registration
- [ ] Set up audit logging
- [ ] Configure rate limiting
- [ ] Review CORS policy
- [ ] Set strong password policy
- [ ] Configure database encryption
- [ ] Set up backup procedures
- [ ] Review security headers

### Post-Deployment

- [ ] Verify HTTPS works
- [ ] Test authentication flow
- [ ] Verify rate limiting
- [ ] Check audit logs
- [ ] Monitor metrics
- [ ] Set up alerts
- [ ] Schedule security updates
- [ ] Plan penetration test

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
