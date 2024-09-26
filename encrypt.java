import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class encrypt {

    public String encrypt(String plainText) throws Exception {

        // Define a fixed salt (in a real system, generate a random salt for each password)
        byte[] salt = Base64.getDecoder().decode("Cbm1NimMH4aHBQTRq1HKiQ==");

        // Define hashing parameters: iterations and key length (128 bits for AES-128)
        KeySpec spec = new PBEKeySpec(plainText.toCharArray(), salt, 1024, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sharedKey = factory.generateSecret(spec);

        // Get the encoded key in byte array format
        byte[] encoded = sharedKey.getEncoded();
        SecretKeySpec key = new SecretKeySpec(encoded, "AES");

        // Initialize Cipher for AES encryption
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Encrypt the plaintext
        byte[] encryptedData = cipher.doFinal(plainText.getBytes());

        // Combine salt and encrypted data
        byte[] saltAndEncryptedData = new byte[salt.length + encryptedData.length];
        System.arraycopy(salt, 0, saltAndEncryptedData, 0, salt.length); // Add salt at the beginning
        System.arraycopy(encryptedData, 0, saltAndEncryptedData, salt.length, encryptedData.length); // Append encrypted data

        // Return Base64 encoded string of combined salt and encrypted data

        System.out.println(Base64.getEncoder().encodeToString(saltAndEncryptedData)); //here for now, plz delete later
        return Base64.getEncoder().encodeToString(saltAndEncryptedData);
    }
}
