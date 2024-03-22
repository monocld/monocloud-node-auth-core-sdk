import { MonoCloudAuthBaseError } from './monocloud-auth-base-error';

export class MonoCloudOPError extends MonoCloudAuthBaseError {
  error_description?: string;

  constructor(error: string, errorDescription?: string) {
    super(error);
    this.error_description = errorDescription;
  }
}
