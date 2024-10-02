package EllipticCurve;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
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

public class Server {
    private static final int PORT = 8888;
    private static final String KEY_SERVER_ADDRESS = "192.168.56.1";
    // private static final String KEY_SERVER_ADDRESS = "localhost";
    private static final int KEY_SERVER_PORT = 9999;
    private static KeyPair keyPair;
    private static PublicKey clientPublicKey;

    // Caching for client public keys
    private static final Map<String, PublicKey> clientKeyCache = new HashMap<>();
    private static final Map<String, Long> cacheTimestamps = new HashMap<>();
    private static final long CACHE_DURATION = 60000; // 60 seconds

    public static void main(String[] args) {
        try {
            // Generate key pair
            keyPair = ECC.generateKeyPair("secp256r1");

            // Store public key in KeyServer
            storePublicKey("Server");

            // Start server socket
            try (ServerSocket serverSocket = new ServerSocket(PORT)) {
                System.out.println("Server started on port " + PORT);

                try (Socket clientSocket = serverSocket.accept();
                     PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                     BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                     Scanner scanner = new Scanner(System.in)) {

                    System.out.println("Client connected: " + clientSocket.getRemoteSocketAddress());

                    while (true) {
                        long startTime = System.currentTimeMillis(); // Reset startTime for new iteration
                        String encryptedMessage = in.readLine();
                        if (encryptedMessage != null) {
                            long receivedTime = System.currentTimeMillis();
                            String decryptedMessage = ECC.decrypt(encryptedMessage, keyPair.getPrivate());
                            System.out.println("Received message from client: " + decryptedMessage);

                            // Get the client public key from cache or key server
                            clientPublicKey = getCachedPublicKey("Client");
                            if (clientPublicKey == null) {
                                System.out.println("Client public key not found.");
                                continue;
                            }

                            System.out.print("Enter message to send to client: ");
                            String responseMessage = scanner.nextLine();
                            String encryptedResponse = Base64.getEncoder().encodeToString(ECC.encrypt(responseMessage, clientPublicKey));
                            long sendTime = System.currentTimeMillis();
                            System.out.println("Sending encrypted response: " + encryptedResponse);
                            out.println(encryptedResponse);
                            // out.flush();

                            // Print latencies
                            System.out.println("Latency for receiving message: " + (receivedTime - startTime) + " ms");
                            System.out.println("Latency for sending response: " + (sendTime - receivedTime) + " ms");
                            
                            // Reset startTime if needed for new operations or logic
                        } else {
                            System.out.println("No message received from client.");
                            if (clientSocket.isClosed() || !clientSocket.isConnected()) {
                                System.out.println("Client disconnected. Waiting for new connection...");
                                break; // Exit loop to accept a new client connection
                            }
                        }
                    }
                }
            } catch (IOException e) {
            }

        } catch (Exception e) {
            // e.printStackTrace();
        }
    }

    private static void storePublicKey(String clientId) throws IOException {
        try (Socket socket = new Socket(KEY_SERVER_ADDRESS, KEY_SERVER_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            out.println("STORE " + clientId);
            String encodedPublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            out.println(encodedPublicKey);
            System.out.println(in.readLine());
        }
    }

    private static PublicKey getCachedPublicKey(String clientId) throws IOException, GeneralSecurityException {
        long currentTime = System.currentTimeMillis();
        if (clientKeyCache.containsKey(clientId) && (currentTime - cacheTimestamps.get(clientId)) < CACHE_DURATION) {
            return clientKeyCache.get(clientId);
        }

        // Fetch from key server if not cached or cache is expired
        try (Socket socket = new Socket(KEY_SERVER_ADDRESS, KEY_SERVER_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

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
            clientKeyCache.put(clientId, publicKey);
            cacheTimestamps.put(clientId, currentTime);

            return publicKey;
        }
    }
}
