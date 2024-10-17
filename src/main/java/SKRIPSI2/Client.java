package SKRIPSI2;

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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

public class Client {

    private static final String KEY_SERVER_ADDRESS = "localhost";
    private static final int KEY_SERVER_PORT = 9999;
    private static final int PORT = 8888;
    private static KeyPair keyPair;

    private static final List<PublicKey> publicKeyCache = new ArrayList<>(); // Menggunakan ArrayList

    public static void main(String[] args) {
        try {
            // Generate key pair
            keyPair = ECC.generateKeyPair("secp256r1");

            // Store public key in KeyServer
            storePublicKey("Client");

            // Retrieve server public key from KeyServer
            PublicKey serverPublicKey = retrievePublicKey("Server");
            if (serverPublicKey != null) {
                publicKeyCache.add(serverPublicKey); // Cache the key
            } else {
                System.out.println("Server public key not found.");
                return;
            }

            // Start client socket
            try (Socket socket = new Socket(KEY_SERVER_ADDRESS, PORT); PrintWriter out = new PrintWriter(socket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream())); Scanner scanner = new Scanner(System.in)) {

                System.out.println("Connected to server: " + socket.getRemoteSocketAddress());

                while (true) {
                    long startTime = System.currentTimeMillis();
                    System.out.print("Enter message to send to server (or 'exit' to quit): ");
                    String message = scanner.nextLine();

                    if (message.equalsIgnoreCase("exit")) {
                        break; // Keluar dari loop jika pengguna mengetik 'exit'
                    }

                    // Encrypt message with server's public key
                    String encryptedMessage = Base64.getEncoder().encodeToString(ECC.encrypt(message, serverPublicKey));
                    System.out.println("Sending encrypted message: " + encryptedMessage);
                    out.println(encryptedMessage);

                    String encryptedResponse = in.readLine();
                    if (encryptedResponse != null) {
                        // Decrypt response from server
                        String decryptedResponse = ECC.decrypt(encryptedResponse, keyPair.getPrivate());
                        long receivedTime = System.currentTimeMillis(); // Waktu menerima pesan
                        // Print latency information
                        System.out.println("Received message from server: " + decryptedResponse);
                        System.out.println("Latency for receiving message: " + (receivedTime - startTime) + " ms");
                    } else {
                        System.out.println("No response from server.");
                        break;
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
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

    private static PublicKey retrievePublicKey(String clientId) throws IOException, GeneralSecurityException {
        try (Socket socket = new Socket(KEY_SERVER_ADDRESS, KEY_SERVER_PORT); PrintWriter out = new PrintWriter(socket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

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
