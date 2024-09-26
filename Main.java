import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.*;

public class Main {

    // Static method to generate salt
    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];  // Salt size: 16 bytes = 128 bits (standard)
        random.nextBytes(salt);  // Fill salt with random bytes
        return salt;
    }

    public static void main(String[] args) throws Exception {
        // Create an instance of the Encrypt class
        encrypt encrypt = new encrypt();

        // Define the password file
        File passwordFile = new File("passwordManager.txt");
        SecretKey key;
        byte[] salt = null;
        String encryptedToken = null;

        // Create a HashMap to store the label-password pairs
        Map<String, String> passwordMap = new HashMap<>();

        // Check if the password file exists
        if (passwordFile.exists()) {
            // Read the salt, encrypted token, and stored passwords from the file
            Scanner fileScanner = new Scanner(passwordFile);
            if (fileScanner.hasNextLine()) {
                String firstLine = fileScanner.nextLine();
                String[] parts = firstLine.split(":");
                salt = Base64.getDecoder().decode(parts[0]);
                encryptedToken = parts[1];
            }

            // Loading the stored passwords into the HashMap
            while (fileScanner.hasNextLine()) {
                String line = fileScanner.nextLine();
                String[] parts = line.split(":");
                if (parts.length == 2) {
                    passwordMap.put(parts[0], parts[1]); // Add label-password pair to HashMap
                }
            }
            fileScanner.close();

            // Ask user for the passcode to access the passwords
            Scanner scanner = new Scanner(System.in);
            System.out.println("Hello and welcome!");
            System.out.print("Enter the passcode to access your passwords: ");
            String passcodeString = scanner.nextLine();

            // Generate the key using the provided passcode and stored salt
            key = encrypt.generateKey(passcodeString, salt);

            // Verify the passcode by decrypting the token
            String decryptedToken = encrypt.decrypt(encryptedToken, key);
            if (!decryptedToken.equals(passcodeString)) {
                System.out.println("Incorrect passcode. Exiting.");
                return;
            }
            else
                System.out.println("Passcode is correct. Access to password manager granted.");
        } else {
            // No password file exists; prompt for an initial password
            Scanner scanner = new Scanner(System.in);
            System.out.println("No password file detected. Please enter an initial passcode:");
            String initialPasscode = scanner.nextLine();

            // Generate salt and create key
            salt = generateSalt();
            key = encrypt.generateKey(initialPasscode, salt);

            // Create password file and write salt and encrypted token
            try (FileWriter fw = new FileWriter(passwordFile)) {
                encryptedToken = encrypt.encrypt(initialPasscode, key); // Encrypt the initial passcode
                fw.write(Base64.getEncoder().encodeToString(salt) + ":" + encryptedToken + "\n");
                System.out.println("Password file created. You can now add passwords.");
            } catch (IOException e) {
                System.err.println("Error while creating the password file: " + e.getMessage());
                return;
            }
        }

        // User menu for adding or reading passwords
        boolean quit = false;
        Scanner scanner = new Scanner(System.in);
        while (!quit) {
            System.out.print("Choose one of the following options\n" +
                    "a : Add Password\n" +
                    "r : Read Password\n" +
                    "q : Quit\n" +
                    "Enter choice: ");
            String choice = scanner.nextLine();

            switch (choice) {
                case "a": // Add a password
                    System.out.print("Enter label for password: ");
                    String label = scanner.nextLine();
                    System.out.print("Enter password to store: ");
                    String password = scanner.nextLine();

                    // Encrypt the password and store it in the HashMap
                    String addedPassword = encrypt.encrypt(password, key);
                    passwordMap.put(label, addedPassword); // Add to HashMap

                    // Append the label and encrypted password to the password file
                    try (FileWriter fw = new FileWriter(passwordFile, true)) {
                        fw.write(label + ":" + addedPassword + "\n");
                    } catch (IOException e) {
                        System.err.println("Error while adding the password: " + e.getMessage());
                    }
                    System.out.println("Password added successfully.");
                    break;

                case "r": // Read a password
                    System.out.print("Enter label for password: ");
                    String givenLabel = scanner.nextLine();

                    // Lookup the encrypted password from the HashMap
                    if (passwordMap.containsKey(givenLabel)) {
                        String encryptedPassword = passwordMap.get(givenLabel);
                        String decryptedPassword = encrypt.decrypt(encryptedPassword, key);
                        System.out.println("Password for " + givenLabel + ": " + decryptedPassword);
                    } else {
                        System.out.println("No password found for the given label.");
                    }
                    break;

                case "q": // Quit
                    System.out.println("Goodbye!");
                    quit = true;
                    break;
            }
        }
    }
}