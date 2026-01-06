package org.example;

import java.util.Arrays;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) throws Exception {
        // Initialize server and client
        Server server = new Server();
        Client client = new Client();

        // Exchange public keys

        System.out.println("client.getPublicKey():"+client.getPublicKey());
        System.out.println("client.getPublicKey():"+client.getPublicKey());
        byte[] serverSecret = server.generateSharedSecret(client.getPublicKey());
        byte[] clientSecret = client.generateSharedSecret(server.getPublicKey());

        System.out.println("Server Shared Secret: " + bytesToHex(serverSecret));
        System.out.println("Client Shared Secret: " + bytesToHex(clientSecret));

        // Check if secrets match
        System.out.println("Shared secret matches: " + Arrays.equals(serverSecret, clientSecret));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}