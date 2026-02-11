import { Injectable, HttpException, HttpStatus, Inject } from '@nestjs/common';
import { Repository, IsNull, DataSource } from 'typeorm';
import { LIB_DATA_SOURCE_TOKEN } from './constants';
import { Request } from 'express';
import * as crypto from 'crypto';
import { ApiKey } from './entities/api-key.entity';
import { SaInfo } from './entities/sa-info.entity';
import { CreateApiKeyDto, ValidateApiKeyDto, UpdateApiKeyDto, ListKeysQueryDto } from './interfaces/dto.interface';
import { KeyGenerationParams } from './interfaces/service.interface';
import { logger } from './utils/logger.util';
import { ApiKeyModel, createApiKeyModel } from './models/api-key.model';
import { KeyGenerationService } from './services/key-generation.service';
import { KeyValidationService } from './services/key-validation.service';

@Injectable()
export class KeyManagerService {
  private apiKeyModel: ApiKeyModel;
  private readonly apiKeyRepo: Repository<ApiKey>;
  private readonly saInfoRepo: Repository<SaInfo>;

  constructor(
    @Inject(LIB_DATA_SOURCE_TOKEN)
    private readonly dataSource: DataSource,
    private readonly keyGenerationService: KeyGenerationService,
    private readonly keyValidationService: KeyValidationService
  ) {
    this.apiKeyRepo = this.dataSource.getRepository(ApiKey);
    this.saInfoRepo = this.dataSource.getRepository(SaInfo);
    this.apiKeyModel = createApiKeyModel(this.apiKeyRepo);
  }

  // Create API key with validation
  async createApiKey(createKeyDto: CreateApiKeyDto, req?: Request) {
    const startTime = Date.now();

    try {
      const { user_id, name, expires_at, description, is_active = true } = createKeyDto;
      logger.info('API key creation initiated', {
        userId: user_id,
        name,
        hasExpiry: !!expires_at,
        description: !!description,
        isActive: is_active,
        endpoint: 'POST /api/keys',
      });

      // Validate expiry date
      let expiryDate: Date | null = null;
      if (expires_at) {
        expiryDate = new Date(expires_at);

        // Check for invalid date
        if (isNaN(expiryDate.getTime())) {
          throw new HttpException(
            {
              error: 'Bad Request',
              message: 'expires_at must be a valid ISO date string',
              code: 'INVALID_EXPIRY_DATE',
              timestamp: new Date().toISOString(),
            },
            HttpStatus.BAD_REQUEST,
          );
        }

        // Check for past date
        if (expiryDate <= new Date()) {
          throw new HttpException(
            {
              error: 'Bad Request',
              message: 'expires_at must be in the future',
              code: 'EXPIRY_DATE_PAST',
              timestamp: new Date().toISOString(),
            },
            HttpStatus.BAD_REQUEST,
          );
        }
      }

      // Step 1: Check if sa_info record exists for user_id
      let saInfo = await this.saInfoRepo.findOne({ 
        where: { 
          user_id,
          deleted_at: IsNull() // Only get non-deleted service accounts
        } 
      });
      
      // Step 2: If not present, create sa_info record
      if (!saInfo) {
        logger.info('Creating new sa_info record', { userId: user_id });
        
        // Generate base64 encoded random bytes for client_secret
        const randomBytes = crypto.randomBytes(32);
        const clientSecret = randomBytes.toString('base64');
        
        const newSaInfo = this.saInfoRepo.create({
          user_id,
          client_secret: clientSecret,
          description: description,
          created_by: 'key-manager-service',
        });
        
        saInfo = await this.saInfoRepo.save(newSaInfo);
        logger.info('sa_info record created', { saInfoId: saInfo.id, userId: user_id });
      } else {
        // Check if the existing sa_info is soft-deleted
        if (saInfo.deleted_at) {
          throw new HttpException(
            {
              error: 'Bad Request',
              message: 'Service account has been deleted',
              code: 'SERVICE_ACCOUNT_DELETED',
              timestamp: new Date().toISOString(),
            },
            HttpStatus.BAD_REQUEST,
          );
        }
        logger.info('Using existing sa_info record', { saInfoId: saInfo.id, userId: user_id });
      }

      // Step 3: Create API key with client_id referencing sa_info id
      const generationParams: KeyGenerationParams = {
        userId: saInfo.id, // Use sa_info id as client_id
        name,
        description,
        isActive: is_active,
        expiresAt: expiryDate,
      };

      const result = await this.keyGenerationService.generateApiKey(generationParams);

      const duration = Date.now() - startTime;
      logger.logOperation('api_key_create', true, {
        userId: user_id,
        clientId: saInfo.id,
        keyId: result.keyId,
        name,
        duration,
        hasExpiry: !!result.expiresAt,
        isActive: is_active,
        endpoint: 'POST /api/keys',
      });

      return {
        success: true,
        message: 'API key created successfully',
        data: {
          key_id: result.keyId,
          raw_key: result.rawKey,
          user_id,
          client_id: saInfo.id,
          client_secret: saInfo.client_secret,
          name,
          description: description || null,
          is_active,
          created_at: result.createdAt,
          expires_at: result.expiresAt,
          status: result.status,
        },
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      logger.logOperation('api_key_create', false, {
        userId: createKeyDto.user_id,
        duration,
        error: errorMessage,
        endpoint: 'POST /api/keys',
      });

      if (error instanceof HttpException) {
        throw error;
      }

      throw new HttpException(
        {
          error: 'Internal Server Error',
          message: 'Failed to create API key',
          code: 'KEY_CREATION_ERROR',
          timestamp: new Date().toISOString(),
          ...(process.env.NODE_ENV === 'development' && { details: errorMessage }),
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // Validate API key
  async validateKey(validateKeyDto: ValidateApiKeyDto) {
    const startTime = Date.now();

    logger.logOperation('api_key_validate_start', true, {
      endpoint: 'POST /keys/validate',
      hasApiKey: !!validateKeyDto.api_key,
      clientId: validateKeyDto.client_id,
      timestamp: new Date().toISOString(),
    });

    try {
      const { client_id, client_secret, api_key } = validateKeyDto;

      // Step 1: Check if client_id exists in sa_info and is not deleted
      const saInfo = await this.saInfoRepo.findOne({ 
        where: { 
          id: client_id,
          deleted_at: IsNull() // Only get non-deleted service accounts
        } 
      });
      
      if (!saInfo) {
        throw new HttpException(
          {
            success: false,
            message: 'Invalid client credentials',
            code: 'INVALID_CLIENT_ID',
            timestamp: new Date().toISOString(),
          },
          HttpStatus.UNAUTHORIZED,
        );
      }

      // Step 2: Verify client_secret
      if (saInfo.client_secret !== client_secret) {
        throw new HttpException(
          {
            success: false,
            message: 'Invalid client credentials',
            code: 'INVALID_CLIENT_SECRET',
            timestamp: new Date().toISOString(),
          },
          HttpStatus.UNAUTHORIZED,
        );
      }

      // Step 3: Validate the API key
      const validationResult = await this.keyValidationService.validateApiKey({
        keyToValidate: api_key,
        clientId: client_id
      });

      const duration = Date.now() - startTime;

      if (!validationResult.isValid) {
        logger.logOperation('api_key_validate', false, {
          reason: validationResult.reason,
          statusCode: validationResult.statusCode,
          duration,
          endpoint: 'POST /keys/validate',
        });

        throw new HttpException(
          {
            success: false,
            message: validationResult.message,
            code: validationResult.reason,
            data: {
              api_key: '***masked***',
              validation_failed_reason: validationResult.reason,
            },
            timestamp: validationResult.timestamp,
            ...(validationResult.details && { details: validationResult.details }),
          },
          validationResult.statusCode,
        );
      }

      logger.logOperation('api_key_validate', true, {
        keyId: validationResult.keyInfo?.id,
        userId: saInfo.user_id,
        clientId: client_id,
        duration,
        endpoint: 'POST /keys/validate',
      });

      return {
        success: true,
        message: 'API key is valid',
        code: 'KEY_VALID',
        data: {
          key_id: validationResult.keyInfo?.id,
          user_id: saInfo.user_id,
          client_id: saInfo.id,
          expires_at: validationResult.keyInfo?.expiresAt,
          status: validationResult.keyInfo?.status,
        },
        timestamp: validationResult.timestamp,
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : 'Unknown validation error';

      logger.logOperation('api_key_validate', false, {
        duration,
        error: errorMessage,
        endpoint: 'POST /keys/validate',
        hasApiKey: !!validateKeyDto.api_key,
      });

      if (error instanceof HttpException) {
        throw error;
      }

      throw new HttpException(
        {
          error: 'Internal Server Error',
          message: 'Validation service error',
          code: 'VALIDATION_SERVICE_ERROR',
          timestamp: new Date().toISOString(),
          ...(process.env.NODE_ENV === 'development' && { details: errorMessage }),
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // Update API key expiry and active status
  async updateApiKey(id: string, updateKeyDto: UpdateApiKeyDto) {
    const startTime = Date.now();

    logger.logOperation('api_key_update_start', true, {
      keyId: id,
      endpoint: 'PUT /keys/:id',
      timestamp: new Date().toISOString(),
    });

    try {
      if (!id) {
        throw new HttpException(
          {
            error: 'Bad Request',
            message: 'Key ID is required',
            code: 'MISSING_KEY_ID',
            timestamp: new Date().toISOString(),
          },
          HttpStatus.BAD_REQUEST,
        );
      }

      const { name, description, expires_at, is_active } = updateKeyDto;

      // Validate at least one field is provided
      if (name === undefined && description === undefined && expires_at === undefined && is_active === undefined) {
        throw new HttpException(
          {
            error: 'Bad Request',
            message: 'At least one field (name, description, expires_at, or is_active) must be provided',
            code: 'MISSING_UPDATE_FIELDS',
            timestamp: new Date().toISOString(),
          },
          HttpStatus.BAD_REQUEST,
        );
      }

      // Find the existing key
      const existingKey = await this.apiKeyRepo.findOne({ where: { id: parseInt(id) } });
      
      if (!existingKey) {
        logger.logOperation('api_key_update', false, {
          keyId: id,
          reason: 'Key not found',
          duration: Date.now() - startTime,
          endpoint: 'PUT /keys/:id',
        });

        throw new HttpException(
          {
            error: 'Not Found',
            message: 'API key not found',
            code: 'KEY_NOT_FOUND',
            timestamp: new Date().toISOString(),
          },
          HttpStatus.NOT_FOUND,
        );
      }

      // Prepare update data
      const updateData: any = {};

      // Set name if provided
      if (name !== undefined) {
        updateData.name = name;
      }

      // Set description if provided
      if (description !== undefined) {
        updateData.description = description;
      }

      // Validate and set expiry date if provided
      if (expires_at !== undefined) {
        const expiryDate = new Date(expires_at);

        // Check for invalid date
        if (isNaN(expiryDate.getTime())) {
          throw new HttpException(
            {
              error: 'Bad Request',
              message: 'expires_at must be a valid ISO date string',
              code: 'INVALID_EXPIRY_DATE',
              timestamp: new Date().toISOString(),
            },
            HttpStatus.BAD_REQUEST,
          );
        }

        // Check for past date
        if (expiryDate <= new Date()) {
          throw new HttpException(
            {
              error: 'Bad Request',
              message: 'expires_at must be in the future',
              code: 'EXPIRY_DATE_PAST',
              timestamp: new Date().toISOString(),
            },
            HttpStatus.BAD_REQUEST,
          );
        }

        updateData.expiry_date = expiryDate;
      }

      // Set is_active if provided
      if (is_active !== undefined) {
        updateData.is_active = is_active;
      }

      // Add updated_by audit field
      updateData.updated_by = 'key-manager-service';

      // Perform the update
      await this.apiKeyRepo.update(parseInt(id), updateData);

      // Fetch the updated key
      const updatedKey = await this.apiKeyRepo.findOne({ where: { id: parseInt(id) } });
      const duration = Date.now() - startTime;

      logger.logOperation('api_key_update', true, {
        keyId: updatedKey!.id,
        clientId: updatedKey!.client_id,
        updatedFields: Object.keys(updateData),
        duration,
        endpoint: 'PUT /keys/:id',
      });

      return {
        success: true,
        message: 'API key updated successfully',
        data: {
          key_id: updatedKey!.id,
          client_id: updatedKey!.client_id,
          name: updatedKey!.name,
          description: updatedKey!.description,
          is_active: updatedKey!.is_active,
          expires_at: updatedKey!.expiry_date,
          status: updatedKey!.is_active ? 'active' : 'inactive',
          updated_at: updatedKey!.updated_at,
        },
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : 'Unknown update error';

      logger.logOperation('api_key_update', false, {
        keyId: id,
        duration,
        error: errorMessage,
        endpoint: 'PUT /keys/:id',
      });

      if (error instanceof HttpException) {
        throw error;
      }

      throw new HttpException(
        {
          error: 'Internal Server Error',
          message: 'Failed to update API key',
          code: 'KEY_UPDATE_ERROR',
          timestamp: new Date().toISOString(),
          ...(process.env.NODE_ENV === 'development' && { details: errorMessage }),
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // Remove API key (soft delete)
  async removeKey(id: string, deletedBy: string = 'key-manager-service') {
    const startTime = Date.now();

    logger.logOperation('api_key_remove_start', true, {
      keyId: id,
      endpoint: 'DELETE /keys/:id',
      timestamp: new Date().toISOString(),
    });

    try {
      if (!id) {
        throw new HttpException(
          {
            error: 'Bad Request',
            message: 'Key ID is required',
            code: 'MISSING_KEY_ID',
            timestamp: new Date().toISOString(),
          },
          HttpStatus.BAD_REQUEST,
        );
      }

      // Find the existing key
      const existingKey = await this.apiKeyRepo.findOne({ where: { id: parseInt(id) } });

      if (!existingKey) {
        logger.logOperation('api_key_remove', false, {
          keyId: id,
          reason: 'Key not found',
          duration: Date.now() - startTime,
          endpoint: 'DELETE /keys/:id',
        });

        throw new HttpException(
          {
            error: 'Not Found',
            message: 'API key not found',
            code: 'KEY_NOT_FOUND',
            timestamp: new Date().toISOString(),
          },
          HttpStatus.NOT_FOUND,
        );
      }

      // Check if already deleted
      if (existingKey.deleted_at) {
        throw new HttpException(
          {
            error: 'Bad Request',
            message: 'API key already deleted',
            code: 'KEY_ALREADY_DELETED',
            timestamp: new Date().toISOString(),
          },
          HttpStatus.BAD_REQUEST,
        );
      }

      // Perform soft delete
      await this.apiKeyRepo.update(parseInt(id), {
        deleted_at: new Date(),
        deleted_by: deletedBy,
        updated_by: deletedBy,
      });

      // Fetch the updated key
      const deletedKey = await this.apiKeyRepo.findOne({ where: { id: parseInt(id) } });
      const duration = Date.now() - startTime;

      logger.logOperation('api_key_remove', true, {
        keyId: deletedKey!.id,
        clientId: deletedKey!.client_id,
        deletedBy,
        duration,
        endpoint: 'DELETE /keys/:id',
      });

      return {
        success: true,
        message: 'API key removed successfully',
        data: {
          key_id: deletedKey!.id,
          client_id: deletedKey!.client_id,
          status: 'deleted',
          deleted_at: deletedKey!.deleted_at,
          deleted_by: deletedKey!.deleted_by,
        },
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : 'Unknown removal error';

      logger.logOperation('api_key_remove', false, {
        keyId: id,
        duration,
        error: errorMessage,
        endpoint: 'DELETE /keys/:id',
      });

      if (error instanceof HttpException) {
        throw error;
      }

      throw new HttpException(
        {
          error: 'Internal Server Error',
          message: 'Failed to remove API key',
          code: 'KEY_REMOVAL_ERROR',
          timestamp: new Date().toISOString(),
          ...(process.env.NODE_ENV === 'development' && { details: errorMessage }),
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // List all API keys with pagination and search
  async listKeys(query: ListKeysQueryDto = {}, req?: Request) {
    const startTime = Date.now();

    logger.logOperation('api_key_list_start', true, {
      endpoint: 'GET /keys',
      query,
      timestamp: new Date().toISOString(),
    });

    try {
      // Parse and validate pagination parameters
      const page = Math.max(1, parseInt(String(query.page || 1)));
      const limit = Math.min(100, Math.max(1, parseInt(String(query.limit || 10))));
      const skip = (page - 1) * limit;

      // Parse sort parameters using database column names
      const sortByColumn = query.sort_by || 'created_at';
      const sortOrderDirection = query.sort_order || 'DESC';

      // Build query with filters
      const queryBuilder = this.apiKeyRepo.createQueryBuilder('api_key')
        .leftJoinAndSelect('api_key.service_account', 'sa_info');

      // Exclude soft-deleted records by default using column name
      if (!query.include_deleted) {
        queryBuilder.andWhere('api_key.deleted_at IS NULL');
      }

      // Apply client_id filter using column name
      if (query.client_id) {
        queryBuilder.andWhere('api_key.client_id = :clientId', { clientId: query.client_id });
      }

      // Apply status filter using column names
      if (query.status) {
        if (query.status === 'active') {
          queryBuilder.andWhere('api_key.is_active = :isActive', { isActive: true });
          queryBuilder.andWhere('api_key.expiry_date > :now', { now: new Date() });
        } else if (query.status === 'inactive' || query.status === 'revoked') {
          queryBuilder.andWhere('api_key.is_active = :isActive', { isActive: false });
        } else if (query.status === 'expired') {
          queryBuilder.andWhere('api_key.expiry_date <= :now', { now: new Date() });
        }
      }

      // Apply search filter using column names (name, description)
      if (query.search) {
        queryBuilder.andWhere(
          '(api_key.name ILIKE :search OR api_key.description ILIKE :search)',
          { search: `%${query.search}%` }
        );
      }

      // Get total count before pagination
      const total = await queryBuilder.getCount();

      // Apply sorting - validate against actual database column names
      const allowedSortColumns = ['created_at', 'updated_at', 'expiry_date', 'name', 'is_active'];
      const validSortColumn = allowedSortColumns.includes(sortByColumn) ? sortByColumn : 'created_at';
      queryBuilder.orderBy(`api_key.${validSortColumn}`, sortOrderDirection);

      // Apply pagination
      queryBuilder.skip(skip).take(limit);

      // Execute query
      const keys = await queryBuilder.getMany();

      const duration = Date.now() - startTime;

      logger.logOperation('api_key_list', true, {
        totalKeys: total,
        returnedKeys: keys.length,
        page,
        limit,
        search: query.search,
        duration,
        endpoint: 'GET /keys',
      });

      return {
        success: true,
        message: 'API keys retrieved successfully',
        data: {
          keys: keys.map((key) => ({
            id: key.id,
            client_id: key.client_id,
            client_secret: key.service_account?.client_secret,
            api_key: key.api_key,
            name: key.name,
            description: key.description,
            created_at: key.created_at,
            expires_at: key.expiry_date,
            status: key.deleted_at 
              ? 'deleted' 
              : !key.is_active 
                ? 'inactive'
                : key.expiry_date <= new Date()
                  ? 'expired'
                  : 'active',
            deleted_at: key.deleted_at,
            deleted_by: key.deleted_by,
          })),
          pagination: {
            page,
            limit,
            total,
            total_pages: Math.ceil(total / limit),
            has_next: page < Math.ceil(total / limit),
            has_previous: page > 1,
          },
        },
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : 'Unknown list error';

      logger.logOperation('api_key_list', false, {
        duration,
        error: errorMessage,
        endpoint: 'GET /keys',
      });

      throw new HttpException(
        {
          error: 'Internal Server Error',
          message: 'Failed to list API keys',
          code: 'KEY_LISTING_ERROR',
          timestamp: new Date().toISOString(),
          ...(process.env.NODE_ENV === 'development' && { details: errorMessage }),
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}