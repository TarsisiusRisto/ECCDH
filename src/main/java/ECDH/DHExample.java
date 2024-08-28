package ECDH;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.KeyAgreement;

public final class DHExample {

    private KeyPair keyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public DHExample() throws Exception {
        generateKeyPair();
    }

    public void generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(2048);
        keyPair = keyPairGen.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public byte[] computeSharedSecret(PublicKey otherPublicKey) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(privateKey);
        keyAgree.doPhase(otherPublicKey, true);
        return keyAgree.generateSecret();
    }

    public static void main(String[] args) throws Exception {
        DHExample alice = new DHExample();
        DHExample bob = new DHExample();

        // Exchange public keys
        PublicKey alicePubKey = alice.getPublicKey();
        PublicKey bobPubKey = bob.getPublicKey();

        // Compute shared secrets
        byte[] aliceSharedSecret = alice.computeSharedSecret(bobPubKey);
        byte[] bobSharedSecret = bob.computeSharedSecret(alicePubKey);

        // Print shared secrets (should be the same)
        System.out.println("Alice's Shared Secret: " + Base64.getEncoder().encodeToString(aliceSharedSecret));
        System.out.println("Bob's Shared Secret: " + Base64.getEncoder().encodeToString(bobSharedSecret));
    }
}
