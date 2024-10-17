package SKRIPSI2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class KeyServer {
    private static final int PORT = 9999;
    private static final List<KeyEntry> keyStore = new ArrayList<>(); // Menggunakan ArrayList

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("KeyServer started on port " + PORT);

            // Simulasi menambahkan 1000 kunci publik random
            for (int i = 1; i <= 1000; i++) {
                try {
                    PublicKey randomPublicKey = ECC.generateKeyPair("secp256r1").getPublic();
                    keyStore.add(new KeyEntry("RandomClient" + i, randomPublicKey)); // Menyimpan kunci dalam ArrayList
                } catch (GeneralSecurityException e) {
                    System.err.println("Failed to generate random public key for RandomClient" + i);
                    e.printStackTrace();
                }
            }

            while (true) {
                new KeyServerHandler(serverSocket.accept()).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class KeyServerHandler extends Thread {
        private final Socket clientSocket;

        public KeyServerHandler(Socket socket) {
            this.clientSocket = socket;
        }

        @Override
        public void run() {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                 PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

                String request = in.readLine();
                if (request.startsWith("STORE")) {
                    String clientID = request.split(" ")[1];
                    String publicKeyStr = in.readLine();
                    PublicKey publicKey = decodePublicKey(publicKeyStr);

                    keyStore.add(new KeyEntry(clientID, publicKey)); // Menyimpan kunci dalam ArrayList
                    out.println("Public key stored successfully.");
                    System.out.println("Stored public key for ID: " + clientID);
                } else if (request.startsWith("RETRIEVE")) {
                    String clientID = request.split(" ")[1];
                    PublicKey publicKey = retrievePublicKey(clientID); // Mengambil kunci dari ArrayList
                    if (publicKey != null) {
                        String encodedKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                        out.println(encodedKey);
                        System.out.println("Retrieved public key for ID: " + clientID);
                    } else {
                        out.println("Key not found for ID: " + clientID);
                    }
                } else {
                    out.println("Invalid request");
                }
                
            } catch (IOException e) {
                e.printStackTrace();
            } catch (GeneralSecurityException ex) {
            }
        }

        // Metode untuk mendekode kunci publik dari string Base64
        private PublicKey decodePublicKey(String publicKeyStr) throws GeneralSecurityException {
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePublic(keySpec);
        }

        private PublicKey retrievePublicKey(String clientID) {
            for (KeyEntry entry : keyStore) {
                if (entry.getClientId().equals(clientID)) {
                    return entry.getPublicKey();
                }
            }
            return null; // Kunci tidak ditemukan
        }
    }
}
