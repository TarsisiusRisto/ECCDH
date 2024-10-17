package ECDH;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECDHExample {

    static {
        // Menambahkan BouncyCastle sebagai security provider
        Security.addProvider(new BouncyCastleProvider());
    }

    // Generate kunci ECC (Elliptic Curve Cryptography)
    private KeyPair generateECCKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1")); // Menggunakan kurva eliptik secp256r1
        return keyPairGenerator.generateKeyPair();
    }

    // Generate shared secret menggunakan ECDH
    private byte[] generateECDHSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret(); // Shared secret dalam bentuk byte[]
    }

    // Enkripsi data menggunakan AES (simetris)
    private byte[] encryptData(SecretKey secretKey, String data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(data.getBytes());
    }

    // Dekripsi data menggunakan AES
    private String decryptData(SecretKey secretKey, byte[] encryptedData, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return new String(cipher.doFinal(encryptedData));
    }

    // Enkripsi kunci simetris dengan ECC
    private byte[] encryptSymmetricKey(SecretKey secretKey, PublicKey eccPublicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, eccPublicKey);
        return cipher.doFinal(secretKey.getEncoded());
    }

    // Dekripsi kunci simetris dengan ECC
    private SecretKey decryptSymmetricKey(byte[] encryptedKey, PrivateKey eccPrivateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, eccPrivateKey);
        byte[] decodedKey = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decodedKey, "AES"); // Mengubah byte[] menjadi SecretKey
    }

    public void execute() throws Exception {
        Scanner scanner = new Scanner(System.in);

        // Generate ECC key pairs untuk Alice dan Bob
        KeyPair aliceKeyPair = generateECCKeyPair();
        KeyPair bobKeyPair = generateECCKeyPair();

        // Step 1: Generate shared secret menggunakan ECDH
        byte[] aliceSharedSecret = generateECDHSharedSecret(aliceKeyPair.getPrivate(), bobKeyPair.getPublic());
        byte[] bobSharedSecret = generateECDHSharedSecret(bobKeyPair.getPrivate(), aliceKeyPair.getPublic());

        // Step 2: Membuat kunci simetris dari shared secret (menggunakan AES)
        SecretKey symmetricKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES"); // Ambil 16 byte untuk AES

        // Step 3: Enkripsi kunci simetris dengan kunci publik ECC
        byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey, bobKeyPair.getPublic());

        // Encode the encrypted symmetric key to Base64
        String base64EncryptedSymmetricKey = Base64.getEncoder().encodeToString(encryptedSymmetricKey);

        // Step 4: Enkripsi data dengan kunci simetris
        System.out.print("Enter Message: ");
        String originalData = scanner.nextLine();
        byte[] iv = new byte[16];
        new java.security.SecureRandom().nextBytes(iv); // Generate random IV
        byte[] encryptedData = encryptData(symmetricKey, originalData, iv);

        // Encode the encrypted data to Base64g
        String base64EncryptedData = Base64.getEncoder().encodeToString(encryptedData);

        // Step 5: Simulasi pengiriman kunci simetris yang terenkripsi dan data terenkripsi
        // Step 6: Dekripsi kunci simetris di sisi penerima (Bob)
        SecretKey decryptedSymmetricKey = decryptSymmetricKey(Base64.getDecoder().decode(base64EncryptedSymmetricKey), bobKeyPair.getPrivate());

        // Step 7: Dekripsi data
        String decryptedData = decryptData(decryptedSymmetricKey, Base64.getDecoder().decode(base64EncryptedData), iv);

        // Output hasil
        System.out.println("Original Data: " + originalData);
        System.out.println("Base64 Encrypted Symmetric Key: " + base64EncryptedSymmetricKey);
        System.out.println("Base64 Encrypted Data: " + base64EncryptedData);
        System.out.println("Decrypted Data: " + decryptedData);
    }

    public static void main(String[] args) {
        try {
            new ECDHExample().execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
