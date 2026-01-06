package org.example;


import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Server {
    private KeyPair keyPair;

    public Server() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        keyPair = kpg.generateKeyPair();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public byte[] generateSharedSecret(PublicKey clientPubKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(keyPair.getPrivate());
        ka.doPhase(clientPubKey, true);
        byte[] sharedSecret = ka.generateSecret();
        return sharedSecret;
    }
}
