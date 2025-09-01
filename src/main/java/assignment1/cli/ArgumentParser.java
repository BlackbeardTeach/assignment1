package assignment1.cli;

public class ArgumentParser {
/**
    * Parses command-line arguments into an ArgumentBundle.
    * 
    * Expected format: java Assignment1 enc|dec -in <file> [-out <file>] 
    *                  [-pass <password>] [-salt <salt.base64>] [-key <key.base64>] 
    *                  [-iv <iv.base64>] [-cipher <cipher>]
    * 
    * @param args Command-line arguments array
    * @return ArgumentBundle containing parsed arguments
    * @throws IllegalArgumentException if arguments are invalid or missing
*/
    public static ArgumentBundle parse(String[] args) throws IllegalArgumentException {
        ArgumentBundle bundle = new ArgumentBundle();

        // Check minimim argument count: at least operation and -in flag with value
        if(args.length < 3) {
            throw new IllegalArgumentException("Insufficient arguments provided.");
        }

        // First argument must be the operation: "enc" or "dec"
        String operation = args[0].toLowerCase();
        if(!operation.equals("enc") && !operation.equals("dec")) {
            throw new IllegalArgumentException("First argument must be 'enc' or 'dec'.");
        }
        bundle.operation = operation;

        // Parse remaining arguments as flag-value pairs
        // Flags can appear in any order after the operation
        for(int i = 1; i < args.length; i++){
            String flag = args[i];

            //Each flag should be followed by a value (except possibly the last one)
            if(i + 1 >= args.length) {
                throw new IllegalArgumentException("Flag " + flag + " requires a value.");
            }

            String value = args[i + 1];
            switch (flag) {
                case "-in":
                    bundle.inputFile = value;
                    break;
                case "-out":
                    bundle.outputFile = value;
                    break;
                case "-pass":
                    bundle.password = value;
                    break;
                case "-salt":
                    bundle.saltFile = value;
                    break;
                case "-key":
                    bundle.keyFile = value;
                    break;
                case "-iv":
                    bundle.ivFile = value;
                    break;
                case "-cipher":
                    bundle.cipher = value;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown flag: " + flag);
            }
            i++; // Skip the value
        }
        // Validate required arguments and combinations
        validateArguments(bundle);

        return bundle;
    }

    /**
     * Validates that the parsed arguments form a valid combination.
     * Checks for required fields and mutually exclusive options.
     * 
     * @param bundle The parsed arguments to validate
     * @throws IllegalArgumentException if validation fails
     */
    private static void validateArguments(ArgumentBundle bundle) throws IllegalArgumentException {
        
        // Input file is always required
        if (bundle.inputFile == null) {
            throw new IllegalArgumentException("Input file (-in) is required");
        }

        // Must have either a direct key OR password+salt (but not neither)
        boolean hasKey = bundle.isDirectKeyUsage();
        boolean hasPasswordAndSalt = bundle.isPasswordBasedKeyDerivation();

        if (!hasKey && !hasPasswordAndSalt) {
            throw new IllegalArgumentException("Must provide either -key or both -pass and -salt");
        }
        
        // If password is provided, salt must also be provided
        if (bundle.password != null && bundle.saltFile == null) {
            throw new IllegalArgumentException("Password (-pass) requires salt file (-salt)");
        }
        
        // If salt is provided, password must also be provided
        if (bundle.saltFile != null && bundle.password == null) {
            throw new IllegalArgumentException("Salt file (-salt) requires password (-pass)");
        }

        // IV validation: required for all modes except ECB
        if (bundle.isIvRequired() && bundle.ivFile == null) {
            String cipher = bundle.getCipherOrDefault();
            throw new IllegalArgumentException("IV (-iv) is required for cipher mode: " + cipher);
        }

        // Validate cipher format if provided
        if (bundle.cipher != null && !isValidCipherFormat(bundle.cipher)) {
            throw new IllegalArgumentException("Invalid cipher format. Expected: aes-{128,192,256}-{ecb,cbc,cfb,ofb,ctr,gcm}");
        }
    }

    /**
     * Validates that the cipher specification follows the expected format.
     * Expected format: aes-{128,192,256}-{ecb,cbc,cfb,ofb,ctr,gcm}
     * 
     * @param cipher The cipher specification to validate
     * @return true if the format is valid, false otherwise
     */
    private static boolean isValidCipherFormat(String cipher) {
        if (cipher == null) {
            return false;
        }
        
        // Split into components: algorithm-keysize-mode
        String[] parts = cipher.toLowerCase().split("-");
        if (parts.length != 3) {
            return false;
        }
        
        // Check algorithm part
        if (!"aes".equals(parts[0])) {
            return false;
        }
        
        // Check key size part
        String keySize = parts[1];
        if (!"128".equals(keySize) && !"192".equals(keySize) && !"256".equals(keySize)) {
            return false;
        }
        
        // Check mode part
        String mode = parts[2];
        return "ecb".equals(mode) || "cbc".equals(mode) || "cfb".equals(mode) || 
               "ofb".equals(mode) || "ctr".equals(mode) || "gcm".equals(mode);
    }
}
