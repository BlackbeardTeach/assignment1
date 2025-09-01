package assignment1.cli;

public class ArgumentBundle {

    // Required: Operation Mode - either "enc" for encryption or "dec" for decryption
    public String operation;

    // Required: Input File Path
    public String inputFile;

    // Optional: Output File Path if null, output goes into stdout
    public String outputFile;

    // Optional: Direct AES key file path (Base64 encoded)
    public String keyFile;

    // Optional: Password for PBKDF2 key derivation
    // Must be used together with saltFile
    public String password;

    // Optional: Salt file path for PBKDF2 key derivation
    // Required when using password-based key derivation (Base64 encoded, 8 bytes)
    public String saltFile;

    // Optional: IV file path (Base64 encoded, 16 bytes for AES)
    public String ivFile;

    // Optional: Cipher specification in format "aes-{128,192,256}-{ecb,cbc,cfb,ofb,ctr,gcm}"
    // Defaults to "aes-256-cbc" if not specified
    public String cipher;

    /** 
     * Constructor initializes all fields to null
     * The ArgumentParser will populate these fields based on command line input
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
     * Checks if password-based key deribvation should be used
     * @return true if both password and saltFile are provided, false otherwise
     */
    public boolean isPasswordBasedKeyDerivation() {
        return this.password != null && this.saltFile != null;
    }

    /** 
     * Checks if direct key should be used
     * @return true if keyFile is provided, false otherwise
     */
    public boolean isDirectKeyUsage() {
        return this.keyFile != null;
    }

    /**
     * Gets the cipher specifications, defaulting to "aes-256-cbc" if not set
     * @return cipher specification string
     */
    public String getCipherOrDefault() {
        return this.cipher != null ? this.cipher : "aes-256-cbc";
    }

    /**
     * Checks if an IV is required based on the cipher mode
     * ECB mode doesn't use an IV, all other modes do
     * @return true if IV is required for the specified cipher mode, false otherwise
     */
    public boolean isIvRequired() {
        String cipherSpec = getCipherOrDefault().toLowerCase();
        // Extract the mode part (eg, "cbc" from "aes-256-cbc")
        String[] parts = cipherSpec.split("-");
        if(parts.length >= 3){
            String mode = parts[2];
            return !"ecb".equals(mode);
        }
        return true;
    }

}
