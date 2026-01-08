package org.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESGCMExample {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 12;       // 96 bits recommended for GCM
    private static final int TAG_SIZE = 128;     // Authentication tag length (bits)

    public static void main(String[] args) throws Exception {

        String plaintext = "Hello AES Encryption!";

        // Generate AES Key
        SecretKey secretKey = generateKey();

        // Encrypt
        EncryptedData encryptedData = encrypt(plaintext, secretKey);
        System.out.println("Encrypted (Base64): " + encryptedData.cipherText);

        // Decrypt
        String decryptedText = decrypt(encryptedData, secretKey);
        System.out.println("Decrypted: " + decryptedText);
    }

    // Generate AES key
    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    // Encrypt plaintext
    private static EncryptedData encrypt(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

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

        GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

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
