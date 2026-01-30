# API Key Management Library

A robust, production-ready NestJS library for managing API keys with service account authentication, soft delete functionality, and comprehensive key lifecycle management.

## Features

✅ **Two-Tier Authentication Architecture**
- User → Service Account → API Keys hierarchy
- Client credential authentication (client_id + client_secret)
- Multiple API keys per service account

✅ **Secure Key Management**
- Base64 encoded random byte generation (32 bytes)
- Automatic service account creation
- Secure client secret handling

✅ **Advanced Key Operations**
- Create API keys with custom metadata (name, description)
- Validate keys with client credentials
- Update key expiry and active status
- Soft delete with audit trails

✅ **Powerful Query Capabilities**
- Page-based pagination (configurable limit, max 100)
- Search by name or description (case-insensitive)
- Sort by multiple fields (created_at, updated_at, expiry_date, name, is_active)
- Filter by client_id, status, and deleted state

✅ **Enterprise-Ready**
- TypeScript with full type definitions
- TypeORM integration for PostgreSQL
- Comprehensive error handling
- Audit logging (created_by, updated_by, deleted_by)
- Soft delete support

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                         User                            │
│                    (user_id: 123)                       │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│                   Service Account                       │
│                      (sa_info)                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │ client_id: "550e8400-e29b-41d4-a716-446655440000" │  │
│  │ client_secret: "base64_encoded_secret"            │  │
│  │ user_id: 123                                      │  │
│  └───────────────────────────────────────────────────┘  │
└───────────────────┬─────────────────────────────────────┘
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
    ┌───────┐   ┌───────┐   ┌───────┐
    │ API   │   │ API   │   │ API   │
    │ Key 1 │   │ Key 2 │   │ Key 3 │
    └───────┘   └───────┘   └───────┘
```

### Database Schema

**sa_info (Service Accounts)**
- `id` (UUID, Primary Key)
- `user_id` (Integer, Foreign Key)
- `client_secret` (String, Unique, Base64 encoded)
- `description` (String, Nullable)
- `created_at`, `updated_at`, `created_by`, `updated_by`
- `deleted_at`, `deleted_by` (Soft delete)

**api_keys**
- `id` (Integer, Primary Key)
- `sa_info_id` (UUID, Foreign Key → sa_info.id)
- `api_key` (String, Base64 encoded, 32 random bytes)
- `name` (String, Required)
- `description` (String, Nullable)
- `is_active` (Boolean, Default: true)
- `expires_at` (Timestamp, Nullable)
- `created_at`, `updated_at`, `created_by`, `updated_by`
- `deleted_at`, `deleted_by` (Soft delete)

## Installation

```bash
npm install key-manager-lib
```

## Quick Start

### 1. Module Setup

```typescript
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { KeyManagerModule } from 'key-manager-lib';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: 'localhost',
      port: 5432,
      username: 'your_username',
      password: 'your_password',
      database: 'your_database',
      entities: [__dirname + '/**/*.entity{.ts,.js}'],
      synchronize: true, // Disable in production
    }),
    KeyManagerModule,
  ],
})
export class AppModule {}
```

### 2. Create Your First API Key

```typescript
import { Controller, Post, Body } from '@nestjs/common';
import { KeyManagerService } from 'key-manager-lib';

@Controller('api/keys')
export class KeyController {
  constructor(private readonly keyManager: KeyManagerService) {}

  @Post()
  async createKey(@Body() dto: any) {
    return await this.keyManager.createApiKey(dto);
  }
}
```

**Request:**
```bash
POST /api/keys
Content-Type: application/json

{
  "user_id": 123,
  "name": "Production API Key",
  "description": "Main production environment key",
  "is_active": true,
  "expires_at": "2027-12-31T23:59:59.000Z"
}
```

**Response:**
```json
{
  "success": true,
  "message": "API key created successfully",
  "data": {
    "key_id": 1,
    "raw_key": "aGVsbG93b3JsZGJhc2U2NGVuY29kZWRrZXk=",
    "client_id": "550e8400-e29b-41d4-a716-446655440000",
    "client_secret": "bXlzZWNyZXRiYXNlNjRlbmNvZGVkc3RyaW5n",
    "name": "Production API Key",
    "description": "Main production environment key",
    "is_active": true,
    "created_at": "2026-01-30T10:00:00.000Z",
    "expires_at": "2027-12-31T23:59:59.000Z",
    "status": "active"
  }
}
```

> ⚠️ **Important**: Save `client_secret` securely! It's only returned when the service account is first created.

### 3. Validate an API Key

```typescript
@Post('validate')
async validateKey(@Body() dto: any) {
  return await this.keyManager.validateKey(dto);
}
```

**Request:**
```bash
POST /api/keys/validate
Content-Type: application/json

{
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "bXlzZWNyZXRiYXNlNjRlbmNvZGVkc3RyaW5n",
  "api_key": "aGVsbG93b3JsZGJhc2U2NGVuY29kZWRrZXk="
}
```

**Response:**
```json
{
  "success": true,
  "message": "API key is valid",
  "code": "KEY_VALID",
  "data": {
    "key_id": 1,
    "user_id": 123,
    "client_id": "550e8400-e29b-41d4-a716-446655440000",
    "expires_at": "2027-12-31T23:59:59.000Z",
    "status": "active"
  }
}
```

## API Endpoints

### Create API Key
```
POST /api/keys
```
Creates a new API key. Automatically creates a service account if this is the user's first key.

**Body Parameters:**
- `user_id` (number, required): User identifier
- `name` (string, required): Display name for the key
- `description` (string, optional): Key description
- `is_active` (boolean, optional): Active status (default: true)
- `expires_at` (ISO 8601, optional): Expiration timestamp

### Validate API Key
```
POST /api/keys/validate
```
Validates an API key with client credentials.

**Body Parameters:**
- `client_id` (UUID, required): Service account client ID
- `client_secret` (string, required): Service account client secret
- `api_key` (string, required): The API key to validate

### Update API Key
```
PUT /api/keys/:id
```
Updates an existing API key's expiry date or active status.

**Body Parameters:**
- `expires_at` (ISO 8601, optional): New expiration timestamp
- `is_active` (boolean, optional): Active status

### Remove API Key
```
DELETE /api/keys/:id
```
Soft deletes an API key (sets deleted_at timestamp).

### List API Keys
```
GET /api/keys?page=1&limit=20&search=production
```
Retrieves API keys with advanced filtering and pagination.

**Query Parameters:**
- `client_id` (UUID, optional): Filter by service account
- `status` (string, optional): Filter by status (active, inactive, expired, deleted)
- `page` (number, optional): Page number (default: 1)
- `limit` (number, optional): Results per page (default: 10, max: 100)
- `search` (string, optional): Search in name/description
- `sort_by` (string, optional): Sort field (created_at, updated_at, expiry_date, name, is_active)
- `sort_order` (string, optional): ASC or DESC (default: DESC)
- `include_deleted` (boolean, optional): Include soft-deleted keys (default: false)

## Development

### Prerequisites
- Node.js >= 14.x
- PostgreSQL >= 12.x
- npm or yarn

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd API-Key-Management
```

2. Install dependencies:
```bash
npm install
```

3. Configure database connection in your environment or `TypeOrmModule.forRoot()`

4. Build the library:
```bash
npm run build
```

5. Run in development mode:
```bash
npm run start:dev
```

### Project Structure

```
src/
├── entities/
│   ├── api-key.entity.ts       # API key database model
│   └── sa-info.entity.ts       # Service account database model
├── interfaces/
│   ├── dto.interface.ts        # Data transfer object types
│   ├── model.interface.ts      # Domain model types
│   └── service.interface.ts    # Service contract types
├── models/
│   └── api-key.model.ts        # Business logic models
├── services/
│   ├── key-generation.service.ts   # Key generation logic
│   └── key-validation.service.ts   # Key validation logic
├── utils/
│   └── logger.util.ts          # Logging utilities
├── key-manager.module.ts       # NestJS module definition
├── key-manager.service.ts      # Main service implementation
└── index.ts                     # Public API exports
```

## Testing

Import the included Postman collection for comprehensive API testing:

```bash
# Located at project root
postman_collection.json
```

**Test Coverage:**
- Service account creation and reuse
- API key CRUD operations
- Validation with client credentials
- Soft delete scenarios
- Pagination and search
- Error handling
- Security tests (SQL injection prevention)

## Error Handling

All endpoints return structured error responses:

```json
{
  "success": false,
  "message": "API key not found or already deleted",
  "code": "KEY_NOT_FOUND",
  "timestamp": "2026-01-30T10:00:00.000Z"
}
```

### Common Error Codes
- `KEY_NOT_FOUND`: API key doesn't exist or is deleted
- `KEY_EXPIRED`: API key has expired
- `KEY_INACTIVE`: API key is not active
- `KEY_ALREADY_DELETED`: Attempting to delete an already deleted key
- `INVALID_CLIENT_CREDENTIALS`: Client ID or secret is incorrect
- `SERVICE_ACCOUNT_NOT_FOUND`: Service account doesn't exist
- `EXPIRY_DATE_PAST`: Expiry date must be in the future
- `INVALID_LIMIT`: Pagination limit exceeds maximum (100)

## Best Practices

1. **Store Credentials Securely**
   - Never commit `client_secret` values to version control
   - Use environment variables or secure vaults
   - Rotate secrets periodically

2. **API Key Lifecycle**
   - Set appropriate expiration dates
   - Monitor expiring keys proactively
   - Remove unused keys promptly

3. **Validation Flow**
   - Always validate both client credentials and API key together
   - Cache validation results with short TTL (if needed)
   - Log validation attempts for security monitoring

4. **Pagination**
   - Use reasonable limit values (10-50) for better performance
   - Implement cursor-based pagination for large datasets if needed

5. **Soft Delete**
   - Soft-deleted records are excluded by default
   - Use `include_deleted=true` only when necessary
   - Implement hard delete policies for compliance (GDPR, etc.)

## Configuration

Environment variables (optional):

```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=your_username
DB_PASSWORD=your_password
DB_DATABASE=api_key_management

# Application
NODE_ENV=production
LOG_LEVEL=info
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see LICENSE file for details

## Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Built with** ❤️ **using NestJS and TypeORM**
