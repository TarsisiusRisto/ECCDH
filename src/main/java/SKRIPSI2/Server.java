package SKRIPSI2;

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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

public class Server {
    private static final int PORT = 8888;
    private static final String KEY_SERVER_ADDRESS = "localhost";
    private static final int KEY_SERVER_PORT = 9999;
    private static KeyPair keyPair;
    private static PublicKey clientPublicKey;

    private static final List<PublicKey> clientKeyCache = new ArrayList<>(); // Menggunakan ArrayList

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
                        long startTime = System.currentTimeMillis();
                        String encryptedMessage = in.readLine();
                        if (encryptedMessage != null) {
                            long receivedTime = System.currentTimeMillis(); // Waktu menerima pesan
                            String decryptedMessage = ECC.decrypt(encryptedMessage, keyPair.getPrivate());
                            System.out.println("Received message from client: " + decryptedMessage);

                            // Get the client public key from cache or key server
                            if (clientPublicKey == null) {
                                clientPublicKey = retrievePublicKey("Client");
                                if (clientPublicKey != null) {
                                    clientKeyCache.add(clientPublicKey); // Cache the key
                                }
                            }

                            if (clientPublicKey == null) {
                                System.out.println("Client public key not found.");
                                continue;
                            }

                            System.out.print("Enter message to send to client: ");
                            String responseMessage = scanner.nextLine();

                            // Simulate latency before sending response
                            long sendTime = System.currentTimeMillis(); // Waktu sebelum mengirim respons
                            String encryptedResponse = Base64.getEncoder().encodeToString(ECC.encrypt(responseMessage, clientPublicKey));
                            System.out.println("Sending encrypted response: " + encryptedResponse);
                            out.println(encryptedResponse);

                            // Print latency information
                            System.out.println("Latency for receiving message: " + (receivedTime - startTime) + " ms");
                            System.out.println("Latency for sending response: " + (sendTime - receivedTime) + " ms");
                        } else {
                            System.out.println("No message received from client.");
                            break;
                        }
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
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

    private static PublicKey retrievePublicKey(String clientId) throws IOException, GeneralSecurityException {
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
            return KeyFactory.getInstance("EC").generatePublic(spec);
        }
    }
}
