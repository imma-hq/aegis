export class Logger {
  static log(component: string, message: string, data?: Record<string, any>) {
    const safeData = data ? { ...data } : undefined;
    // Remove any sensitive data from logs
    if (safeData) {
      const sensitiveKeys = [
        "secretKey",
        "privateKey",
        "rootKey",
        "chainKey",
        "ciphertext",
      ];
      sensitiveKeys.forEach((key) => delete safeData[key]);
    }
    console.log(`[${component}] ${message}`, safeData || "");
  }

  static error(component: string, message: string, error?: any) {
    console.error(`[${component}] ERROR: ${message}`, error || "");
  }

  static warn(component: string, message: string, data?: Record<string, any>) {
    console.warn(`[${component}] WARN: ${message}`, data || "");
  }
}
