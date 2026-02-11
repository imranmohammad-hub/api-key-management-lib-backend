import { Module, Global } from '@nestjs/common';
import { KeyManagerService } from './key-manager.service';
import { KeyGenerationService } from './services/key-generation.service';
import { KeyValidationService } from './services/key-validation.service';

@Global()
@Module({
  providers: [
    KeyManagerService,
    KeyGenerationService,
    KeyValidationService,
  ],
  exports: [KeyManagerService, KeyGenerationService, KeyValidationService],
})
export class KeyManagerModule {}
