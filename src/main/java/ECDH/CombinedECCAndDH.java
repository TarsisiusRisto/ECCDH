package ECDH;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CombinedECCAndDH {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair generateECCKeyPair(String curveName) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec(curveName));
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateDHKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] computeSharedSecretECC(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    public static byte[] computeSharedSecretDH(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    public static byte[] encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    public static String decrypt(String encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedMessage)), StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        // Generate ECC key pairs for two parties (Alice and Bob)
        KeyPair aliceECCKeyPair = generateECCKeyPair("secp256r1");
        KeyPair bobECCKeyPair = generateECCKeyPair("secp256r1");

        // Generate DH key pairs for two parties (Alice and Bob)
        KeyPair aliceDHKeyPair = generateDHKeyPair();
        KeyPair bobDHKeyPair = generateDHKeyPair();

        // Compute shared secrets using Diffie-Hellman
        byte[] aliceSharedSecretDH = computeSharedSecretDH(aliceDHKeyPair.getPrivate(), bobDHKeyPair.getPublic());
        byte[] bobSharedSecretDH = computeSharedSecretDH(bobDHKeyPair.getPrivate(), aliceDHKeyPair.getPublic());

        // Optionally, you could derive a shared secret using ECC as well
        byte[] aliceSharedSecretECC = computeSharedSecretECC(aliceECCKeyPair.getPrivate(), bobECCKeyPair.getPublic());
        byte[] bobSharedSecretECC = computeSharedSecretECC(bobECCKeyPair.getPrivate(), aliceECCKeyPair.getPublic());

        // Alice encrypts a message using Bob's ECC public key
        String message = "Hello Bob, this is a secret message!";
        byte[] encryptedMessage = encrypt(message, bobECCKeyPair.getPublic());
        String encodedEncryptedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
        System.out.println("Encrypted Message: " + encodedEncryptedMessage);

        // Bob decrypts the message using his ECC private key
        String decryptedMessage = decrypt(encodedEncryptedMessage, bobECCKeyPair.getPrivate());
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
}
