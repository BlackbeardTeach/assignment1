package assignment1.cli;

import assignment1.crypto.CipherUtils;
import assignment1.crypto.Decryptor;
import assignment1.crypto.Encryptor;

/**
 * CLIApplication is the main entry point that orchestrates argument parsing,
 * validation, and dispatching to encryption or decryption operations.
 */
public class CLIApplication {

    /**
     * Main entry point for the CLI application.
     * Parses arguments, validates inputs, and dispatches to appropriate crypto operation.
     * 
     * @param argv Command-line arguments
     * @return Status code indicating success or type of failure
     */
    public static int run(String[] argv) {
        ArgumentBundle args;
        
        // Step 1: Parse command-line arguments
        try {
            args = ArgumentParser.parse(argv);
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            return StatusCode.INVALID_ARGUMENTS;
        }

        // Step 2: Validate file existence and accessibility
        try {
            // Input file must exist and be readable
            CipherUtils.validateFileExists(args.inputFile, "Input");
            
            // Key file must exist if using direct key
            if (args.useDirectKey()) {
                CipherUtils.validateFileExists(args.keyFile, "Key");
            }
            
            // Salt file must exist if using password derivation
            if (args.usePasswordDerivation()) {
                CipherUtils.validateFileExists(args.saltFile, "Salt");
            }
            
            // IV file must exist if required for the cipher mode
            if (args.isIvRequired() && args.ivFile != null) {
                CipherUtils.validateFileExists(args.ivFile, "IV");
            }
            
            // Output path validation (if specified)
            if (args.outputFile != null) {
                CipherUtils.validateOutputPath(args.outputFile);
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            
            // Determine appropriate status code based on error type
            String errorMsg = e.getMessage().toLowerCase();
            if (errorMsg.contains("does not exist")) {
                return StatusCode.FILE_NOT_FOUND;
            } else if (errorMsg.contains("not readable")) {
                return StatusCode.FILE_NOT_READABLE;
            } else if (errorMsg.contains("writ") || errorMsg.contains("directory")) {
                return StatusCode.FILE_WRITE_ERROR;
            } else {
                return StatusCode.UNKNOWN_ERROR;
            }
        }

        // Step 3: Validate cryptographic parameters before attempting operations
        try {
            // Validate cipher specification
            String cipherSpec = args.getCipherOrDefault();
            String transformation = CipherUtils.cipherSpecToTransformation(cipherSpec);
            int expectedKeySize = CipherUtils.getKeySize(cipherSpec);
            
            // Validate key if using direct key
            if (args.useDirectKey()) {
                byte[] keyBytes = CipherUtils.readBase64File(args.keyFile);
                CipherUtils.createDirectKey(keyBytes, expectedKeySize); // This validates key length
            }
            
            // Validate salt if using password derivation
            if (args.usePasswordDerivation()) {
                byte[] saltBytes = CipherUtils.readBase64File(args.saltFile);
                if (saltBytes.length != 8) {
                    System.err.println("Error: Salt must be exactly 8 bytes, got " + saltBytes.length);
                    return StatusCode.INVALID_SALT;
                }
            }
            
            // Validate IV if required
            if (args.isIvRequired() && args.ivFile != null) {
                byte[] ivBytes = CipherUtils.readBase64File(args.ivFile);
                // For most modes, IV should be 16 bytes (AES block size)
                // GCM can accept 12 or 16 bytes, but we'll be flexible
                if (ivBytes.length != 16 && ivBytes.length != 12) {
                    System.err.println("Error: IV must be 12 or 16 bytes, got " + ivBytes.length);
                    return StatusCode.INVALID_IV;
                }
            }
            
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            String errorMsg = e.getMessage().toLowerCase();
            
            if (errorMsg.contains("cipher")) {
                return StatusCode.UNSUPPORTED_CIPHER;
            } else if (errorMsg.contains("key")) {
                return StatusCode.INVALID_KEY;
            } else if (errorMsg.contains("iv")) {
                return StatusCode.INVALID_IV;
            } else if (errorMsg.contains("salt")) {
                return StatusCode.INVALID_SALT;
            } else {
                return StatusCode.INVALID_ARGUMENTS;
            }
        } catch (Exception e) {
            System.err.println("Error validating parameters: " + e.getMessage());
            String errorMsg = e.getMessage().toLowerCase();
            
            // Handle Base64 decoding errors and file reading errors
            if (errorMsg.contains("base64")) {
                if (errorMsg.contains("key")) return StatusCode.INVALID_KEY;
                if (errorMsg.contains("iv")) return StatusCode.INVALID_IV;
                if (errorMsg.contains("salt")) return StatusCode.INVALID_SALT;
            }
            
            return StatusCode.UNKNOWN_ERROR;
        }

        // Step 4: Dispatch to appropriate operation
        if ("enc".equals(args.operation)) {
            return Encryptor.run(args);
        } else if ("dec".equals(args.operation)) {
            return Decryptor.run(args);
        } else {
            // This should never happen if ArgumentParser is working correctly
            System.err.println("Error: Unknown operation: " + args.operation);
            return StatusCode.INVALID_ARGUMENTS;
        }
    }
}