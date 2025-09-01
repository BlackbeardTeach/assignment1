package assignment1.crypto;

import assignment1.cli.ArgumentBundle;
import assignment1.cli.StatusCode;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.io.FileOutputStream;
import java.io.IOException;

public class Encryptor {
    /**
     * Performs AES encryption based on the provided arguments.
     * 
     * @param args ArgumentBundle containing all necessary parameters
     * @return StatusCode indicating success or failure type
     */
    public static int run(ArgumentBundle args) {
        try {
            // Step 1: Prepare the AES key
            SecretKeySpec secretKey;
            String cipherSpec = args.getCipherOrDefault();
            int keySize = CipherUtils.getKeySize(cipherSpec);

            if(args.useDirectKey()){
                // use direct key from file
                byte[] keyBytes = CipherUtils.readBase64File(args.keyFile);
                secretKey = CipherUtils.createDirectKey(keyBytes, keySize);
            } else {
                // derive key from password using PBKDF2
                byte[] saltBytes = CipherUtils.readBase64File(args.saltFile);
                secretKey = CipherUtils.deriveKeyFromPassword(args.password, saltBytes, keySize);
            }

            // Step 2: Prepare the initialization vector (IV) (if required)
            byte[] iv = null;
            if(args.isIvRequired()){
                if(args.ivFile == null){
                    System.err.println("Error: IV is required for cipher mode but not provided");
                    return StatusCode.INVALID_ARGUMENTS;
                }
                iv = CipherUtils.readBase64File(args.ivFile);
            }

            // Step 3: Initialize the cipher for encryption
            Cipher cipher = CipherUtils.createCipher(cipherSpec, Cipher.ENCRYPT_MODE, secretKey, iv);

            // Step 4: Read input file
            Path inputPath = Paths.get(args.inputFile);
            byte[] plaintext;

            try {
                plaintext = Files.readAllBytes(inputPath);
            } catch (IOException e) {
                System.err.println("Error reading input file: " + e.getMessage());
                return StatusCode.FILE_NOT_READABLE;
            }

            // Step 5: Perform encryption
            byte[] ciphertext;
            try {
                ciphertext = cipher.doFinal(plaintext);
            } catch (Exception e) {
                System.err.println("Error during encryption: " + e.getMessage());
                return StatusCode.ENCRYPTION_ERROR;
            }

            // Step 6: Write output
            if(args.outputFile != null){
                // Write to specified output file
                try{
                    Path outputPath = Paths.get(args.outputFile);
                    Files.write(outputPath, ciphertext);
                } catch (IOException e) {
                    System.err.println("Error writing output file: " + e.getMessage());
                    return StatusCode.FILE_WRITE_ERROR;
                }
            } else {
                // Write to stdout 
                try {
                    System.out.write(ciphertext);
                    System.out.flush();
                } catch (IOException e) {
                    System.err.println("Error writing to stdout: " + e.getMessage());
                    return StatusCode.FILE_WRITE_ERROR;
                }
            }

            return StatusCode.SUCCESS;
        } catch (IllegalArgumentExceptionException e) {
            // Handle validation errors
            System.err.println("Error: " + e.getMessage());
            String errorMsg = e.getMessage().toLowerCase();
            
            if (errorMsg.contains("key")) {
                return StatusCode.INVALID_KEY;
            } else if (errorMsg.contains("iv")) {
                return StatusCode.INVALID_IV;
            } else if (errorMsg.contains("salt")) {
                return StatusCode.INVALID_SALT;
            } else if (errorMsg.contains("cipher")) {
                return StatusCode.UNSUPPORTED_CIPHER;
            } else {
                return StatusCode.INVALID_ARGUMENTS;
            }
        } catch (Exception e) {
            // Handle any other errors during encryption process
            System.err.println("Error during encryption: " + e.getMessage());
            return StatusCode.ENCRYPTION_ERROR;
        }
    }
}
