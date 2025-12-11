# AegisAI API Endpoints

This document lists all available API endpoints in the AegisAI enterprise platform.

## Agent Management

### Register New Agent
- **POST** `/api/v1/agents/register`
- Register a new endpoint agent with the cloud backend

### Agent Heartbeat
- **POST** `/api/v1/agents/heartbeat`
- Send heartbeat signal from agent to maintain connection status

### Get Agent Status
- **GET** `/api/v1/agents`
- Retrieve status information for all connected agents

## File Analysis

### Submit File for Analysis
- **POST** `/api/v1/analysis/file`
- Submit a file for cloud-based threat analysis

## Threat Intelligence

### Query Threat Intelligence
- **GET** `/api/v1/threat-intel`
- Query threat intelligence database for indicators

### Update Threat Intelligence
- **POST** `/api/v1/threat-intel/update`
- Update threat intelligence feeds or add custom indicators

### Get Threat Intelligence Statistics
- **GET** `/api/v1/threat-intel/stats`
- Retrieve statistics about threat intelligence database

## Policy Management

### Get Agent Policy
- **GET** `/api/v1/policies/{agent_id}`
- Retrieve security policy for a specific agent

### Update Policies
- **POST** `/api/v1/policies/update`
- Update security policies for agents

## Compliance Reporting

### Generate Compliance Report
- **GET** `/api/v1/compliance/report`
- Generate compliance report based on current data

### Privacy Notice
- **GET** `/api/v1/privacy`
- Retrieve privacy notice for compliance purposes

### CCPA Notice
- **GET** `/api/v1/ccpa`
- Retrieve CCPA notice for compliance purposes

### Data Access Request
- **POST** `/api/v1/data-access`
- Handle user data access requests

### Data Erasure Request
- **POST** `/api/v1/data-erasure`
- Handle user data erasure requests

## Incident Management

### Report Security Incident
- **POST** `/api/v1/incidents/report`
- Report a security incident from an agent

## Real-time Communication

### WebSocket Connection
- **GET** `/api/v1/ws/{agent_id}`
- Establish WebSocket connection for real-time communication

## Enterprise Dashboard APIs

### Executive Dashboard
- **GET** `/api/v1/dashboard/executive`
- Retrieve executive dashboard with overall security posture

### Threat Intelligence Dashboard
- **GET** `/api/v1/dashboard/threat-intel`
- Retrieve detailed threat intelligence dashboard

### Compliance Dashboard
- **GET** `/api/v1/dashboard/compliance`
- Retrieve detailed compliance dashboard

### Incident Response Dashboard
- **GET** `/api/v1/dashboard/incident-response`
- Retrieve detailed incident response dashboard

### Endpoint Security Dashboard
- **GET** `/api/v1/dashboard/endpoints`
- Retrieve detailed endpoint security dashboard

## Authentication and Security

All API endpoints (except agent registration) require authentication using Bearer token in the Authorization header:

```
Authorization: Bearer <auth_token>
```

Tokens are generated during agent registration and are valid for 24 hours.

## Rate Limiting

API endpoints implement rate limiting to prevent abuse:
- 100 requests per minute per agent
- 1000 requests per hour per agent

Exceeding rate limits will result in HTTP 429 (Too Many Requests) responses.

## Error Handling

API responses follow standard HTTP status codes:
- 200: Success
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 429: Too Many Requests
- 500: Internal Server Error

Error responses include a JSON body with error details:

```json
{
  "status": "error",
  "message": "Description of the error"
}
```

## Response Format

Successful API responses follow this format:

```json
{
  "status": "success",
  "data": {
    // Response data
  }
}
```

## WebSocket Communication

Real-time communication with agents is handled through WebSocket connections:
- Connection endpoint: `/api/v1/ws/{agent_id}`
- Messages are sent as JSON objects
- Supports bidirectional communication for immediate threat response

## Data Formats

All API requests and responses use JSON format with UTF-8 encoding.

## Versioning

API endpoints are versioned using URL path versioning:
- Current version: v1
- Version prefix: `/api/v1/`

## Security Considerations

- All communication should use HTTPS in production
- API tokens should be stored securely
- Input validation is performed on all endpoints
- Rate limiting prevents abuse
- IP blocking for suspicious activity