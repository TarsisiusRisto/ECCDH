// package ECDH;

// import java.io.BufferedReader;
// import java.io.IOException;
// import java.io.InputStreamReader;
// import java.io.PrintWriter;
// import java.net.ServerSocket;
// import java.net.Socket;
// import java.security.KeyFactory;
// import java.security.KeyPair;
// import java.security.PrivateKey;
// import java.security.PublicKey;
// import java.security.spec.X509EncodedKeySpec;
// import java.util.Base64;

// public class Server extends Thread {
//     private static final String[] CURVE_OPTIONS = {"secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1"};

//     private final Socket clientSocket;
//     private final PublicKey serverPublicKey;
//     private final PrivateKey serverPrivateKey;
//     private PublicKey clientPublicKey;
//     private PrintWriter out;
//     private BufferedReader in;

//     public Server(Socket clientSocket, PublicKey serverPublicKey, PrivateKey serverPrivateKey) {
//         this.clientSocket = clientSocket;
//         this.serverPublicKey = serverPublicKey;
//         this.serverPrivateKey = serverPrivateKey;
//     }

//     @Override
//     public void run() {
//         try {
//             in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
//             out = new PrintWriter(clientSocket.getOutputStream(), true);

//             // Sending chosen curve and server public key to the client
//             out.println(CURVE_OPTIONS[4]); // Using secp256r1 by default
//             out.println(Base64.getEncoder().encodeToString(serverPublicKey.getEncoded()));

//             // Receiving client's public key
//             String clientPublicKeyStr = in.readLine();
//             if (clientPublicKeyStr != null) {
//                 byte[] clientPublicKeyBytes = Base64.getDecoder().decode(clientPublicKeyStr);
//                 clientPublicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(clientPublicKeyBytes));

//                 // Creating a thread to receive messages from the client
//                 new Thread(() -> {
//                     try {
//                         String message;
//                         while ((message = in.readLine()) != null) {
//                             if (message.equalsIgnoreCase("quit")) {
//                                 break;
//                             }
//                             System.out.println("Message from client: " + message);
//                             String decryptedMessage = DHECCExample.decrypt(Base64.getDecoder().decode(message), DHECCExample.performDHKeyAgreement(serverPrivateKey, clientPublicKey), serverPrivateKey);
//                             System.out.println("Message from client (decrypted): " + decryptedMessage);
//                         }
//                     } catch (Exception e) {
//                         e.printStackTrace();
//                     } finally {
//                         try {
//                             clientSocket.close();
//                         } catch (IOException e) {
//                             e.printStackTrace();
//                         }
//                     }
//                 }).start();
//             }
//         } catch (Exception e) {
//             e.printStackTrace();
//         }
//     }

//     public static void main(String[] args) {
//         try {
//             KeyPair keyPair = DHECCExample.generateECCKeyPair("secp256r1");
//             ServerSocket serverSocket = new ServerSocket(8888);
//             System.out.println("Server started on port 8888");

//             while (true) {
//                 Socket clientSocket = serverSocket.accept();
//                 System.out.println("Client connected: " + clientSocket.getInetAddress());
//                 Server server = new Server(clientSocket, keyPair.getPublic(), keyPair.getPrivate());
//                 server.start();
//             }
//         } catch (Exception e) {
//             e.printStackTrace();
//         }
//     }
// }
