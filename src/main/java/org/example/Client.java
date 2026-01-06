package org.example;

import java.security.*;
import javax.crypto.*;

public class Client {
    private KeyPair keyPair;

    public Client() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        keyPair = kpg.generateKeyPair();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public byte[] generateSharedSecret(PublicKey serverPubKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(keyPair.getPrivate());
        ka.doPhase(serverPubKey, true);
        byte[] sharedSecret = ka.generateSecret();
        return sharedSecret;
    }
}

