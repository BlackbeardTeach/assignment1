package assignment1.crypto;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CipherUtils provides utility functions for cryptographic operations.
 * Handles key derivation, Base64 decoding, and cipher initialization.
 */
public class CipherUtils {
    
    // PBKDF2 configuration as specified in assignment
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int SALT_LENGTH_BYTES = 8;
    private static final int AES_BLOCK_SIZE_BYTES = 16;
    private static final int GCM_TAG_LENGTH_BITS = 128; // 16 bytes * 8 bits/byte

    /**
     * Derives an AES key from a password using PBKDF2.
     * Uses HMAC-SHA256 with 65536 iterations as specified in the assignment.
     * 
     * @param password The password string
     * @param salt The salt bytes (must be 8 bytes)
     * @param keyLengthBits The desired key length in bits (128, 192, or 256)
     * @return SecretKeySpec for AES encryption
     * @throws Exception if key derivation fails
     */
    public static SecretKeySpec deriveKeyFromPassword(String password, byte[] salt, int keyLengthBits) throws Exception {
        
        // Validate salt length
        if (salt.length != SALT_LENGTH_BYTES) {
            throw new IllegalArgumentException("Salt must be exactly " + SALT_LENGTH_BYTES + " bytes, got " + salt.length);
        }
        
        // Convert key length from bits to bytes
        int keyLengthBytes = keyLengthBits / 8;
        
        // Create key specification for PBKDF2
        // Convert password to char array as required by PBEKeySpec
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, keyLengthBits);
        
        // Get PBKDF2 secret key factory
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        
        // Generate the key using PBKDF2
        byte[] derivedKey = factory.generateSecret(keySpec).getEncoded();
        
        // Create AES key specification from derived bytes
        return new SecretKeySpec(derivedKey, "AES");
    }

    /**
     * Creates an AES SecretKeySpec from raw key bytes.
     * 
     * @param keyBytes The raw key bytes
     * @param expectedLengthBits Expected key length in bits for validation
     * @return SecretKeySpec for AES encryption
     * @throws IllegalArgumentException if key length doesn't match expected
     */
    public static SecretKeySpec createDirectKey(byte[] keyBytes, int expectedLengthBits) throws IllegalArgumentException {
        int expectedLengthBytes = expectedLengthBits / 8;
        
        if (keyBytes.length != expectedLengthBytes) {
            throw new IllegalArgumentException(
                "Key length mismatch: expected " + expectedLengthBytes + " bytes (" + expectedLengthBits + " bits), got " + keyBytes.length
            );
        }
        
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Reads and decodes a Base64-encoded file.
     * 
     * @param filePath Path to the Base64-encoded file
     * @return Decoded bytes
     * @throws Exception if file reading or Base64 decoding fails
     */
    public static byte[] readBase64File(String filePath) throws Exception {
        // Read the entire file as a string
        Path path = Paths.get(filePath);
        String base64Content = Files.readString(path).trim(); // Remove any whitespace
        
        // Decode from Base64
        try {
            return Base64.getDecoder().decode(base64Content);
        } catch (IllegalArgumentException e) {
            throw new Exception("Invalid Base64 content in file: " + filePath, e);
        }
    }

    /**
     * Converts cipher specification (e.g., "aes-256-cbc") to JCE transformation string.
     * 
     * @param cipherSpec Cipher specification in assignment format
     * @return JCE transformation string (e.g., "AES/CBC/PKCS5Padding")
     * @throws IllegalArgumentException if cipher specification is invalid
     */
    public static String cipherSpecToTransformation(String cipherSpec) throws IllegalArgumentException {
        String[] parts = cipherSpec.toLowerCase().split("-");
        
        if (parts.length != 3 || !"aes".equals(parts[0])) {
            throw new IllegalArgumentException("Invalid cipher specification: " + cipherSpec);
        }
        
        String mode = parts[2].toUpperCase();
        String padding;
        
        // Determine padding based on mode
        switch (mode) {
            case "ECB":
            case "CBC":
                // Block modes use PKCS5 padding
                padding = "PKCS5Padding";
                break;
            case "CFB":
            case "OFB":
            case "CTR":
            case "GCM":
                // Stream modes and authenticated modes use no padding
                padding = "NoPadding";
                break;
            default:
                throw new IllegalArgumentException("Unsupported cipher mode: " + mode);
        }
        
        return "AES/" + mode + "/" + padding;
    }

    /**
     * Extracts the key size in bits from cipher specification.
     * 
     * @param cipherSpec Cipher specification (e.g., "aes-256-cbc")
     * @return Key size in bits (128, 192, or 256)
     * @throws IllegalArgumentException if cipher specification is invalid
     */
    public static int getKeySize(String cipherSpec) throws IllegalArgumentException {
        String[] parts = cipherSpec.toLowerCase().split("-");
        
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid cipher specification: " + cipherSpec);
        }
        
        try {
            int keySize = Integer.parseInt(parts[1]);
            if (keySize != 128 && keySize != 192 && keySize != 256) {
                throw new IllegalArgumentException("Invalid key size: " + keySize + ". Must be 128, 192, or 256");
            }
            return keySize;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid key size in cipher spec: " + parts[1]);
        }
    }

    /**
     * Creates and initializes a Cipher object for the specified operation.
     * 
     * @param cipherSpec Cipher specification (e.g., "aes-256-cbc")
     * @param mode Cipher mode: Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     * @param key The AES secret key
     * @param iv The initialization vector (null for ECB mode)
     * @return Initialized Cipher object ready for encryption/decryption
     * @throws Exception if cipher initialization fails
     */
    public static Cipher createCipher(String cipherSpec, int mode, SecretKeySpec key, byte[] iv) throws Exception {
        
        // Convert our cipher spec to JCE transformation format
        String transformation = cipherSpecToTransformation(cipherSpec);
        
        // Create cipher instance
        Cipher cipher = Cipher.getInstance(transformation);
        
        // Get the mode from cipher spec for IV handling
        String[] parts = cipherSpec.toLowerCase().split("-");
        String cipherMode = parts[2];
        
        // Initialize cipher based on mode requirements
        if ("ecb".equals(cipherMode)) {
            // ECB mode doesn't use an IV
            cipher.init(mode, key);
        } else if ("gcm".equals(cipherMode)) {
            // GCM mode uses GCMParameterSpec for authentication
            if (iv == null) {
                throw new IllegalArgumentException("GCM mode requires an IV");
            }
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(mode, key, gcmSpec);
        } else {
            // All other modes (CBC, CFB, OFB, CTR) use regular IvParameterSpec
            if (iv == null) {
                throw new IllegalArgumentException("Mode " + cipherMode + " requires an IV");
            }
            if (iv.length != AES_BLOCK_SIZE_BYTES) {
                throw new IllegalArgumentException("IV must be " + AES_BLOCK_SIZE_BYTES + " bytes for AES, got " + iv.length);
            }
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(mode, key, ivSpec);
        }
        
        return cipher;
    }

    /**
     * Validates that a file exists and is readable.
     * 
     * @param filePath Path to the file to check
     * @param fileType Description of file type for error messages (e.g., "input", "key", "IV")
     * @throws Exception if file doesn't exist or isn't readable
     */
    public static void validateFileExists(String filePath, String fileType) throws Exception {
        Path path = Paths.get(filePath);
        
        if (!Files.exists(path)) {
            throw new Exception(fileType + " file does not exist: " + filePath);
        }
        
        if (!Files.isReadable(path)) {
            throw new Exception(fileType + " file is not readable: " + filePath);
        }
        
        if (Files.isDirectory(path)) {
            throw new Exception(fileType + " path is a directory, not a file: " + filePath);
        }
    }

    /**
     * Checks if an output file path is valid for writing.
     * Creates parent directories if they don't exist.
     * 
     * @param outputPath Path where output should be written
     * @throws Exception if the path is not writable
     */
    public static void validateOutputPath(String outputPath) throws Exception {
        Path path = Paths.get(outputPath);
        
        // Check if path points to an existing directory
        if (Files.exists(path) && Files.isDirectory(path)) {
            throw new Exception("Output path is a directory, not a file: " + outputPath);
        }
        
        // Check parent directory exists or can be created
        Path parentDir = path.getParent();
        if (parentDir != null && !Files.exists(parentDir)) {
            throw new Exception("Output directory does not exist: " + parentDir);
        }
        
        // If file exists, check if it's writable (will be overwritten)
        if (Files.exists(path) && !Files.isWritable(path)) {
            throw new Exception("Cannot write to output file: " + outputPath);
        }
    }
}