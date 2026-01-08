package org.example;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AES256CBCExample {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding"; // CBC mode requires padding
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 16; // 128-bit IV for AES

    public static void main(String[] args) throws Exception {
        String plaintext = "Hello AES-256-CBC Encryption!";

        // Generate AES Key
        SecretKey secretKey = generateKey();

        // Encrypt
        EncryptedData encryptedData = encrypt(plaintext, secretKey);
        System.out.println("Encrypted (Base64): " + encryptedData.cipherText);
        System.out.println("IV (Base64): " + encryptedData.iv);

        // Decrypt
        String decryptedText = decrypt(encryptedData, secretKey);
        System.out.println("Decrypted: " + decryptedText);
    }

    // Generate AES key
    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE);
        return keyGen.generateKey();
    }

    // Encrypt plaintext
    private static EncryptedData encrypt(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        // Generate random IV
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        return new EncryptedData(
                Base64.getEncoder().encodeToString(cipherText),
                Base64.getEncoder().encodeToString(iv)
        );
    }

    // Decrypt ciphertext
    private static String decrypt(EncryptedData encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        byte[] iv = Base64.getDecoder().decode(encryptedData.iv);
        byte[] cipherText = Base64.getDecoder().decode(encryptedData.cipherText);

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] decrypted = cipher.doFinal(cipherText);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // Helper class to hold encrypted data
    private static class EncryptedData {
        String cipherText;
        String iv;

        EncryptedData(String cipherText, String iv) {
            this.cipherText = cipherText;
            this.iv = iv;
        }
    }
}
