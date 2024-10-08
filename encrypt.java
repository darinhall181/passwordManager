import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class encrypt {

    // Method to generate a random salt
    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];  // Salt size: 16 bytes = 128 bits (standard)
        random.nextBytes(salt);  // Fill salt with random bytes
        return salt;
    }

    // PBKDF2 Key generation method
    public static SecretKey generateKey(String passcode, byte[] salt) throws Exception {
        int iterations = 1024;
        int keyLength = 256;  // For AES-256

        KeySpec spec = new PBEKeySpec(passcode.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); //instance of sha256 encryption
        byte[] encoded = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(encoded, "AES");
    }

    // Encrypt method using AES
    public static String encrypt(String plainText, SecretKey key) throws Exception {
        // Initialize the cipher for AES encryption
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Encrypt the plaintext
        byte[] encryptedData = cipher.doFinal(plainText.getBytes());

        // Return the encrypted data as a Base64 encoded string
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // Decrypt method using AES
    public static String decrypt(String encryptedText, SecretKey key) throws Exception {
        // Initialize the cipher for AES decryption
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        // Decode the Base64-encoded encrypted text
        byte[] encryptedData = Base64.getDecoder().decode(encryptedText);

        // Decrypt the data
        byte[] decryptedData = cipher.doFinal(encryptedData);

        // Return the decrypted plaintext
        return new String(decryptedData);
    }
/*
    public static void main(String[] args) throws Exception {
        String passcode = "mySecretPasscode";

        // Generate a random salt
        byte[] salt = generateSalt();
        System.out.println("Generated Salt (Base64): " + Base64.getEncoder().encodeToString(salt));

        // Generate key using PBKDF2
        SecretKey key = generateKey(passcode, salt);

        // Example token to encrypt (e.g., "spaghetti")
        String token = "spaghetti";

        // Encrypt the token
        String encryptedToken = encrypt(token, key);
        System.out.println("Encrypted Token: " + encryptedToken);

        // Decrypt the token to verify
        String decryptedToken = decrypt(encryptedToken, key);
        System.out.println("Decrypted Token: " + decryptedToken);
    }
 */
}