export class Logger {
    static log(component, message, data) {
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
    static error(component, message, error) {
        console.error(`[${component}] ERROR: ${message}`, error || "");
    }
    static warn(component, message, data) {
        console.warn(`[${component}] WARN: ${message}`, data || "");
    }
}
