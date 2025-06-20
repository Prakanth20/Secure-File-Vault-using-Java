import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class SecureFileVault {

    static Scanner scanner = new Scanner(System.in);
    static Map<String, String> users = new HashMap<>(); // username -> password hash
    static Map<String, String> roles = new HashMap<>(); // username -> role
    static SecretKey aesKey;

    static {
        try {
            aesKey = generateAESKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws Exception {
        users.put("admin", hash("admin123"));
        roles.put("admin", "ADMIN");

        while (true) {
            System.out.println("\n== Secure File Vault ==");
            System.out.print("Username: ");
            String username = scanner.nextLine();

            System.out.print("Password: ");
            String password = scanner.nextLine();

            if (authenticate(username, password)) {
                String role = roles.get(username);
                System.out.println("Login successful! Role: " + role);
                if (role.equals("ADMIN")) {
                    adminMenu(username);
                } else {
                    userMenu(username);
                }
            } else {
                System.out.println("Invalid login.");
            }
        }
    }

    static boolean authenticate(String username, String password) {
        return users.containsKey(username) && users.get(username).equals(hash(password));
    }

    static void adminMenu(String username) throws Exception {
        while (true) {
            System.out.println("\n[ADMIN MENU]");
            System.out.println("1. Create User");
            System.out.println("2. Upload File");
            System.out.println("3. Download File");
            System.out.println("4. View Users");
            System.out.println("5. Logout");

            switch (scanner.nextLine()) {
                case "1":
                    System.out.print("New username: ");
                    String newUser = scanner.nextLine();
                    System.out.print("Password: ");
                    String newPass = scanner.nextLine();
                    System.out.print("Role (ADMIN/USER): ");
                    String newRole = scanner.nextLine().toUpperCase();
                    users.put(newUser, hash(newPass));
                    roles.put(newUser, newRole);
                    System.out.println("User created.");
                    break;
                case "2":
                    uploadFile(username);
                    break;
                case "3":
                    downloadFile();
                    break;
                case "4":
                    System.out.println("Users:");
                    roles.forEach((user, role) -> System.out.println(user + " - " + role));
                    break;
                case "5":
                    return;
                default:
                    System.out.println("Invalid choice.");
            }
        }
    }

    static void userMenu(String username) throws Exception {
        while (true) {
            System.out.println("\n[USER MENU]");
            System.out.println("1. Upload File");
            System.out.println("2. Download File");
            System.out.println("3. Logout");

            switch (scanner.nextLine()) {
                case "1":
                    uploadFile(username);
                    break;
                case "2":
                    downloadFile();
                    break;
                case "3":
                    return;
                default:
                    System.out.println("Invalid choice.");
            }
        }
    }

    static void uploadFile(String username) throws Exception {
        System.out.print("Path to file: ");
        String path = scanner.nextLine();
        File inputFile = new File(path);
        if (!inputFile.exists()) {
            System.out.println("File not found.");
            return;
        }

        byte[] fileData = Files.readAllBytes(inputFile.toPath());
        byte[] encrypted = encrypt(fileData, aesKey);
        String vaultPath = "vault/" + username + "_" + inputFile.getName();

        Files.createDirectories(Paths.get("vault"));
        Files.write(Paths.get(vaultPath), encrypted);
        System.out.println("File encrypted and saved to vault.");
    }

    static void downloadFile() throws Exception {
        System.out.print("Filename in vault (e.g., user_file.txt): ");
        String fileName = scanner.nextLine();
        Path filePath = Paths.get("vault/" + fileName);
        if (!Files.exists(filePath)) {
            System.out.println("File not found.");
            return;
        }

        byte[] encrypted = Files.readAllBytes(filePath);
        byte[] decrypted = decrypt(encrypted, aesKey);

        System.out.print("Save decrypted file as: ");
        String outputPath = scanner.nextLine();
        Files.write(Paths.get(outputPath), decrypted);
        System.out.println("File decrypted and saved.");
    }

    // === Crypto Utilities ===
    static SecretKey generateAESKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // 256 requires JCE policy files in some JDKs
        return generator.generateKey();
    }

    static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    static byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    static String hash(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(digest.digest(password.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
