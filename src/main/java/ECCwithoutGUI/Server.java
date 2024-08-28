package ECCwithoutGUI;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Server {
    private static final String[] CURVE_OPTIONS = {"secp192r1", "secp224k1", "secp224r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1"};
    private PublicKey serverPublicKey;
    private PrivateKey serverPrivateKey;
    private String chosenCurve;
    private Handler currentHandler;

    public Server() {
        chooseCurve();
        generateKeyPair();
        startServer();
    }

    private void chooseCurve() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Supported Curve:");
        for (int i = 0; i < CURVE_OPTIONS.length; i++) {
            System.out.println((i + 1) + ". " + CURVE_OPTIONS[i]);
        }
        System.out.print("Choose a curve : ");
        int choice = scanner.nextInt();
        chosenCurve = CURVE_OPTIONS[choice - 1];
        System.out.println("Selected Curve: " + chosenCurve);
    }

    private void generateKeyPair() {
        try {
            KeyPair keyPair = ECC.generateKeyPair(chosenCurve);
            serverPublicKey = keyPair.getPublic();
            serverPrivateKey = keyPair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(8888)) {
            System.out.println("Server started on port " + serverSocket.getLocalPort());
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket.getInetAddress());
                currentHandler = new Handler(clientSocket, serverPublicKey, serverPrivateKey);
                currentHandler.start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private class Handler extends Thread {
        private final Socket clientSocket;
        private final PublicKey serverPublicKey;
        private final PrivateKey serverPrivateKey;
        private PublicKey clientPublicKey;
        private PrintWriter out;
        private BufferedReader in;
        private long lastSendTime;
    
        public Handler(Socket clientSocket, PublicKey serverPublicKey, PrivateKey serverPrivateKey) {
            this.clientSocket = clientSocket;
            this.serverPublicKey = serverPublicKey;
            this.serverPrivateKey = serverPrivateKey;
        }
    
        @Override
        public void run() {
            try {
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                out = new PrintWriter(clientSocket.getOutputStream(), true);
    
                out.println(chosenCurve);
                String encodedPublicKey = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
                out.println(encodedPublicKey);
    
                String clientPublicKeyStr = in.readLine();
                byte[] clientPublicKeyBytes = Base64.getDecoder().decode(clientPublicKeyStr);
                clientPublicKey = KeyFactory.getInstance("EC", "BC").generatePublic(new X509EncodedKeySpec(clientPublicKeyBytes));
    
                new Thread(() -> {
                    try {
                        String message;
                        while ((message = in.readLine()) != null) {
                            if (message.equalsIgnoreCase("quit")) {
                                break;
                            }
    
                            long receiveTime = System.currentTimeMillis();
                            String decryptedMessage = ECC.decrypt(message, serverPrivateKey);
    
                            System.out.println("\nClient (before decryption): " + message);
                            System.out.println("Client: " + decryptedMessage);
    
                            long latency = receiveTime - lastSendTime;
                            System.out.println("Latency: " + latency + " ms");
                            System.out.print("Enter Message: ");
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }).start();
    
                // Menambahkan kemampuan server untuk mengirim pesan ke client
                Scanner scanner = new Scanner(System.in);
                while (true) {
                    System.out.print("Enter Message: ");
                    String message = scanner.nextLine();
                    if (message.equalsIgnoreCase("quit")) {
                        out.println("quit");
                        break;
                    }
                    sendMessage(message);
                }
    
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    clientSocket.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    
        public void sendMessage(String message) {
            try {
                lastSendTime = System.currentTimeMillis();
                byte[] encryptedMessage = ECC.encrypt(message, clientPublicKey);
                String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
    
                System.out.println("Server (before encryption): " + message);
                System.out.println("Server (encrypted): " + encodedMessage);
    
                out.println(encodedMessage);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        new Server();
    }
}