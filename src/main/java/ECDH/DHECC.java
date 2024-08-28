package ECDH;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DHECC {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private KeyPair keyPair;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecretKeySpec sharedSecretKey;

    public DHECC() {
        generateKeyPair();
    }

    public DHECC(String curveName) throws Exception {
        generateKeyPair(curveName);
    }

    public void generateKeyPair() {
        generateKeyPair("secp256r1");
    }

    public void generateKeyPair(String curveName) {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("ECDH", "BC");
            keyPairGen.initialize(new ECGenParameterSpec(curveName));
            keyPair = keyPairGen.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public byte[] computeSharedSecret(PublicKey otherPublicKey) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH", "BC");
        keyAgree.init(privateKey);
        keyAgree.doPhase(otherPublicKey, true);
        byte[] sharedSecret = keyAgree.generateSecret();

        // Derive key for AES encryption/decryption from shared secret
        sharedSecretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
        return sharedSecret;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public SecretKeySpec getSharedSecretKey() {
        return sharedSecretKey;
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, sharedSecretKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, sharedSecretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        DHECC server = new DHECC();
        DHECC client = new DHECC();

        // Exchange public keys and compute shared secret
        byte[] serverSharedSecret = client.computeSharedSecret(server.getPublicKey());
        byte[] clientSharedSecret = server.computeSharedSecret(client.getPublicKey());

        if (MessageDigest.isEqual(serverSharedSecret, clientSharedSecret)) {
            System.out.println("Shared secrets match.");
        } else {
            System.out.println("Shared secrets do not match.");
        }

        // Test encryption and decryption
        String message = "Hello, this is a secret message!";
        String encryptedMessage = client.encrypt(message);
        String decryptedMessage = server.decrypt(encryptedMessage);

        System.out.println("Original Message: " + message);
        System.out.println("Encrypted Message: " + encryptedMessage);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
}
