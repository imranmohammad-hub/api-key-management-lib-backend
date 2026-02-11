import { Injectable, Inject } from '@nestjs/common';
import { Repository, DataSource } from 'typeorm';
import { LIB_DATA_SOURCE_TOKEN } from '../constants';
import * as crypto from 'crypto';
import { ApiKey } from '../entities/api-key.entity';
import { KeyGenerationParams, KeyGenerationResult, KeyGenerationServiceConfig, UniqueKeyResult } from '../interfaces/service.interface';
import { logger } from '../utils/logger.util';

// Service for secure API key generation with collision detection
@Injectable()
export class KeyGenerationService {
    private config: KeyGenerationServiceConfig = {
        saltRounds: 12,
        maxRetries: 3,
        keyPrefix: 'ak_',
        defaultExpiryDays: 365
    };

    private readonly apiKeyRepository: Repository<ApiKey>;

    constructor(
        @Inject(LIB_DATA_SOURCE_TOKEN)
        private readonly dataSource: DataSource
    ) {
        this.apiKeyRepository = this.dataSource.getRepository(ApiKey);
    }

    // Generate base64 encoded API key
    generateRawKey(): string {
        const randomBytes = crypto.randomBytes(32);
        return randomBytes.toString('base64');
    }

    // Check if a key already exists in database
    async checkKeyExists(apiKey: string): Promise<boolean> {
        try {
            // Search for existing key in api_key column
            const existing = await this.apiKeyRepository.findOne({
                where: {
                    api_key: apiKey
                }
            });

            return !!existing;
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown collision check error';
            logger.info('Collision check failed', { error: errorMessage });
            throw new Error(`Collision check failed: ${errorMessage}`);
        }
    }

    // Generate unique API key with collision detection and retry logic
    async generateUniqueKey(
        userId: string,
        name: string,
        description: string | undefined,
        isActive: boolean,
        expiresAt: Date | null = null
    ): Promise<UniqueKeyResult> {
        let attempt = 0;

        while (attempt < this.config.maxRetries) {
            try {
                // Generate raw key
                const rawKey = this.generateRawKey();

                // Check for collision
                const exists = await this.checkKeyExists(rawKey);

                if (!exists) {
                    // No collision, create the key record
                    const keyRecord = await this.createKeyRecord(rawKey, userId, name, description, isActive, expiresAt);

                    // Log successful generation
                    await this.logKeyGeneration(keyRecord.id.toString(), userId.toString(), 'success');

                    return {
                        rawKey, // Return raw key only once
                        keyRecord: {
                            id: keyRecord.id.toString(),
                            userId: keyRecord.client_id,
                            createdAt: keyRecord.created_at,
                            expiresAt: keyRecord.expiry_date,
                            status: keyRecord.is_active ? 'active' : 'inactive'
                        }
                    };
                }

                // Collision detected, retry
                attempt++;
                logger.info('Key collision detected, retrying', { attempt, userId });

            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown generation error';
                await this.logKeyGeneration(null, userId.toString(), 'error', { error: errorMessage, attempt });
                throw error;
            }
        }

        // Maximum retries exceeded
        const errorMessage = `Failed to generate unique key after ${this.config.maxRetries} attempts`;
        const error = new Error(errorMessage);
        await this.logKeyGeneration(null, userId.toString(), 'error', { error: errorMessage });
        throw error;
    }

    // Create key record in database with metadata
    async createKeyRecord(
        apiKey: string,
        userId: string,
        name: string,
        description: string | undefined,
        isActive: boolean,
        expiresAt: Date | null
    ): Promise<ApiKey> {
        try {
            // Create the database entity with comprehensive metadata
            const entity = this.apiKeyRepository.create({
                name,
                client_id: userId,
                api_key: apiKey, // Store base64 encoded key
                expiry_date: expiresAt || new Date(Date.now() + this.config.defaultExpiryDays * 24 * 60 * 60 * 1000),
                is_active: isActive,
                created_by: 'key-generation-service',
                description: description || `Generated API key for client ${userId}`
            });

            // Persist to database
            const saved = await this.apiKeyRepository.save(entity);

            if (!saved) {
                throw new Error('No key record returned from database');
            }

            return saved;
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown database error';
            logger.info('Failed to create key record', { error: errorMessage });
            throw new Error(`Failed to create key record: ${errorMessage}`);
        }
    }

    // Log key generation operation for audit and monitoring
    async logKeyGeneration(
        keyId: string | null,
        userId: string,
        result: string,
        details: Record<string, any> = {}
    ): Promise<void> {
        try {
            const logDetails = {
                operation_type: 'create',
                key_id: keyId,
                user_id: userId,
                result,
                timestamp: new Date().toISOString(),
                bcrypt_rounds: this.config.saltRounds,
                ...details
            };

            logger.info('Key generation operation', logDetails);
        } catch (error) {
            // Don't throw on logging errors, just warn
            const errorMessage = error instanceof Error ? error.message : 'Unknown logging error';
            logger.info('Failed to log key generation', { error: errorMessage });
        }
    }

    // Validate key generation input parameters
    validateGenerationInput(userId: string, expiresAt: Date | null): void {
        // Validate user ID
        if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
            throw new Error('Client ID is required and must be a non-empty string');
        }

        // Validate expiry date
        if (expiresAt !== null) {
            if (!(expiresAt instanceof Date)) {
                throw new Error('Expiry date must be a Date object or null');
            }

            if (expiresAt <= new Date()) {
                throw new Error('Expiry date must be in the future');
            }
        }
    }

    // Main method: generate API key with validation, collision detection, and error handling
    async generateApiKey(params: KeyGenerationParams): Promise<KeyGenerationResult> {
        const { userId, name, description, isActive = true, expiresAt = null } = params;
        const startTime = Date.now();

        try {
            // Validate input parameters
            this.validateGenerationInput(userId, expiresAt);

            // Generate the unique key with collision detection
            const result = await this.generateUniqueKey(userId, name, description, isActive, expiresAt);

            const generationTime = Date.now() - startTime;

            logger.info('API key generated successfully', { userId, generationTime });

            return {
                keyId: result.keyRecord.id,
                rawKey: result.rawKey,
                userId: result.keyRecord.userId,
                createdAt: result.keyRecord.createdAt,
                expiresAt: result.keyRecord.expiresAt,
                status: result.keyRecord.status
            };

        } catch (error) {

            // Log the error
            const generationTime = Date.now() - startTime;
            const errorMessage = error instanceof Error ? error.message : 'Unknown generation error';
            logger.info('Key generation failed', { userId, generationTime, error: errorMessage });
            throw error;
        }
    }

    // Get service configuration
    getConfig(): KeyGenerationServiceConfig {
        return { ...this.config };
    }

    // Update service configuration
    updateConfig(newConfig: Partial<KeyGenerationServiceConfig>): void {
        this.config = { ...this.config, ...newConfig };
        logger.info('Key generation service configuration updated', newConfig);
    }
}