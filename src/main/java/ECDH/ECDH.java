package ECDH;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECDH {

    static {
        // Menambahkan BouncyCastle sebagai security provide
        Security.addProvider(new BouncyCastleProvider());
    }

    // Generate kunci ECC (Elliptic Curve Cryptography)
    public KeyPair generateECCKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1")); // Menggunakan kurva eliptik secp256r1
        return keyPairGenerator.generateKeyPair();
    }

    public static PublicKey getPublicKeyFromEncoded(byte[] encodedKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
    }

    // Generate shared secret menggunakan ECDH
    public static byte[] generateECDHSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret(); // Shared secret dalam bentuk byte[]
    }

    // Enkripsi data menggunakan AES (simetris)
    public static byte[] encryptData(SecretKey secretKey, String data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(data.getBytes());
    }

    // Dekripsi data menggunakan AES
    public static String decryptData(SecretKey secretKey, byte[] encryptedData, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return new String(cipher.doFinal(encryptedData));
    }

    // Enkripsi kunci simetris dengan ECC
    public static byte[] encryptSymmetricKey(SecretKey secretKey, PublicKey eccPublicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, eccPublicKey);
        return cipher.doFinal(secretKey.getEncoded());
    }

    // Dekripsi kunci simetris dengan ECC
    public static SecretKey decryptSymmetricKey(byte[] encryptedKey, PrivateKey eccPrivateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, eccPrivateKey);
        byte[] decodedKey = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decodedKey, "AES"); // Mengubah byte[] menjadi SecretKey
    }
}
