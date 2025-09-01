package assignment1.cli;

public class ArgumentBundle {
    
    // Required: Operation mode - either "enc" for encryption or "dec" for decryption
    public String operation;
    
    // Required: Path to input file to be encrypted or decrypted
    public String inputFile;
    
    // Optional: Path to output file. If null, output goes to stdout
    public String outputFile;
    
    // Optional: Direct AES key file path (Base64 encoded)
    // If provided, takes precedence over password-based derivation
    public String keyFile;
    
    // Optional: Password for PBKDF2 key derivation
    // Must be used together with saltFile
    public String password;
    
    // Optional: Salt file path (Base64 encoded, 8 bytes)
    // Required when using password-based key derivation
    public String saltFile;
    
    // Optional: IV file path (Base64 encoded, typically 16 bytes for AES)
    // Required for all modes except ECB
    public String ivFile;
    
    // Optional: Cipher specification in format "aes-{128,192,256}-{ecb,cbc,cfb,ofb,ctr,gcm}"
    // Defaults to "aes-256-cbc" if not specified
    public String cipher;
    
    /**
     * Constructor initializes all fields to null.
     * The ArgumentParser will populate these fields based on command-line input.
     */
    public ArgumentBundle() {
        this.operation = null;
        this.inputFile = null;
        this.outputFile = null;
        this.keyFile = null;
        this.password = null;
        this.saltFile = null;
        this.ivFile = null;
        this.cipher = null;
    }
    
    /**
     * Checks if password-based key derivation should be used.
     * @return true if password and salt are both provided
     */
    public boolean usePasswordDerivation() {
        return password != null && saltFile != null;
    }
    
    /**
     * Checks if direct key should be used.
     * @return true if keyFile is provided
     */
    public boolean useDirectKey() {
        return keyFile != null;
    }
    
    /**
     * Gets the cipher specification, defaulting to "aes-256-cbc" if not set.
     * @return cipher specification string
     */
    public String getCipherOrDefault() {
        return cipher != null ? cipher : "aes-256-cbc";
    }
    
    /**
     * Checks if an IV is required based on the cipher mode.
     * ECB mode doesn't use an IV, all other modes do.
     * @return true if IV is required for the specified cipher mode
     */
    public boolean isIvRequired() {
        String cipherSpec = getCipherOrDefault().toLowerCase();
        // Extract the mode part (e.g., "cbc" from "aes-256-cbc")
        String[] parts = cipherSpec.split("-");
        if (parts.length >= 3) {
            String mode = parts[2];
            return !"ecb".equals(mode);
        }
        return true; // Default to requiring IV if we can't parse the cipher
    }
}