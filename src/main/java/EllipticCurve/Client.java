package EllipticCurve;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Client {

    private static final String KEY_SERVER_ADDRESS = "localhost";
    private static final int KEY_SERVER_PORT = 9999;
    private static KeyPair keyPair;
    private static final Map<String, PublicKey> publicKeyCache = new HashMap<>();
    private static final Map<String, Long> cacheTimestamps = new HashMap<>();
    private static final long CACHE_DURATION = 60000; // 60 seconds

    public static void main(String[] args) {
        try {
            // Generate key pair
            keyPair = ECC.generateKeyPair("secp256r1");

            // Store public key in KeyServer
            storePublicKey("Client");

            // Retrieve server public key from KeyServer
            PublicKey serverPublicKey = getCachedPublicKey("Server");
            if (serverPublicKey == null) {
                System.out.println("Server public key not found.");
                return;
            }

            // Start client socket
            try (Socket socket = new Socket(KEY_SERVER_ADDRESS, 8888); PrintWriter out = new PrintWriter(socket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream())); Scanner scanner = new Scanner(System.in)) {

                System.out.println("Connected to server: " + socket.getRemoteSocketAddress());
                while (true) {
                    long startTime = System.currentTimeMillis(); // Reset startTime for new iteration
                    System.out.print("Enter message to send to server: ");
                    String message = scanner.nextLine();
                    String encryptedMessage = Base64.getEncoder().encodeToString(ECC.encrypt(message, serverPublicKey));
                    System.out.println("Sending encrypted message: " + encryptedMessage);
                    out.println(encryptedMessage);
                    out.flush();

                    // Read response from server
                    String encryptedResponse = in.readLine();
                    if (encryptedResponse != null) {
                        String decryptedResponse = ECC.decrypt(encryptedResponse, keyPair.getPrivate());
                        long receivedTime = System.currentTimeMillis();
                        System.out.println("Received decrypted response: " + decryptedResponse);

                        // Print latency
                        System.out.println("Latency for sending message: " + (receivedTime - startTime) + " ms");
                    } else {
                        System.out.println("No response received.");
                        break;
                    }
                }
            } catch (IOException e) {
                // e.printStackTrace();
            }
        } catch (Exception e) {
            // e.printStackTrace();
        }
    }

    private static void storePublicKey(String clientId) throws IOException {
        try (Socket socket = new Socket(KEY_SERVER_ADDRESS, KEY_SERVER_PORT); PrintWriter out = new PrintWriter(socket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            out.println("STORE " + clientId);
            String encodedPublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            out.println(encodedPublicKey);
            System.out.println(in.readLine());
        }
    }

    private static PublicKey getCachedPublicKey(String clientId) throws IOException, GeneralSecurityException {
        long currentTime = System.currentTimeMillis();
        if (publicKeyCache.containsKey(clientId) && (currentTime - cacheTimestamps.get(clientId)) < CACHE_DURATION) {
            return publicKeyCache.get(clientId);
        }

        // Fetch from key server if not cached or cache is expired
        try (Socket socket = new Socket(KEY_SERVER_ADDRESS, KEY_SERVER_PORT); PrintWriter out = new PrintWriter(socket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            out.println("RETRIEVE " + clientId);
            String response = in.readLine();
            if (response.startsWith("Key not found")) {
                return null;
            }

            byte[] keyBytes = Base64.getDecoder().decode(response);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            PublicKey publicKey = keyFactory.generatePublic(spec);

            // Update cache
            publicKeyCache.put(clientId, publicKey);
            cacheTimestamps.put(clientId, currentTime);

            return publicKey;
        }
    }
}
