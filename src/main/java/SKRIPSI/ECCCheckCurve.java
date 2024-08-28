package SKRIPSI;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Enumeration;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECCCheckCurve {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        // Mendapatkan semua nama kurva yang terdaftar
        @SuppressWarnings("unchecked")
        Enumeration<String> curveNames = ECNamedCurveTable.getNames();

        // Memeriksa setiap kurva
        while (curveNames.hasMoreElements()) {
            String curveName = curveNames.nextElement();
            if (isCurveSupported(curveName)) {
                System.out.println(curveName + " is supported.");
            } else {
                System.out.println(curveName + " is NOT supported.");
            }
        }
    }

    public static boolean isCurveSupported(String curveName) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            keyPairGenerator.initialize(ecSpec);
            return true;
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            return false;
        }
    }
}