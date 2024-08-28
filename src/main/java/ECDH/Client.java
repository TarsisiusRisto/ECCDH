// package ECDH;

// import java.io.BufferedReader;
// import java.io.IOException;
// import java.io.InputStreamReader;
// import java.io.PrintWriter;
// import java.net.Socket;
// import java.security.KeyFactory;
// import java.security.KeyPair;
// import java.security.PublicKey;
// import java.security.spec.X509EncodedKeySpec;
// import java.util.Base64;

// public class Client extends Thread {
//     private final Socket clientSocket;
//     private final KeyPair keyPair;
//     private PublicKey serverPublicKey;
//     private PrintWriter out;
//     private BufferedReader in;

//     public Client(String serverAddr, int serverPort, KeyPair keyPair) throws IOException {
//         this.clientSocket = new Socket(serverAddr, serverPort);
//         this.keyPair = keyPair;
//         this.serverPublicKey = null; // Server public key will be received from the server

//         // Initialize input and output streams
//         out = new PrintWriter(clientSocket.getOutputStream(), true);
//         in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

//         // Send client's public key to the server
//         out.println(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

//         // Receive server's public key
//         try {
//             String serverPublicKeyStr = in.readLine();
//             byte[] serverPublicKeyBytes = Base64.getDecoder().decode(serverPublicKeyStr);
//             serverPublicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(serverPublicKeyBytes));
//         } catch (Exception e) {
//             e.printStackTrace();
//         }

//         // Create a thread to continuously listen for messages from the server
//         new Thread(() -> {
//             try {
//                 String message;
//                 while ((message = in.readLine()) != null) {
//                     if (message.equalsIgnoreCase("quit")) {
//                         break;
//                     }
//                     System.out.println("Message from server before decryption: " + message);
//                     String decryptedMessage = DHECCExample.decrypt(Base64.getDecoder().decode(message), DHECCExample.performDHKeyAgreement(keyPair.getPrivate(), serverPublicKey), keyPair.getPrivate());
//                     System.out.println("Message from server (decrypted): " + decryptedMessage);
//                 }
//             } catch (Exception e) {
//                 e.printStackTrace();
//             }
//         }).start();
//     }

//     public void sendMessage(String message) {
//         try {
//             if (out != null) {
//                 byte[] encryptedMessage = DHECCExample.encrypt(message, DHECCExample.performDHKeyAgreement(keyPair.getPrivate(), serverPublicKey), serverPublicKey);
//                 String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
//                 out.println(encodedMessage);
//                 System.out.println("Encrypted message sent to server: " + encodedMessage);
//             }
//         } catch (Exception e) {
//             e.printStackTrace();
//         }
//     }

//     @Override
//     public void run() {
//         // Perform any additional tasks after initialization, if needed
//     }

//     public static void main(String[] args) {
//         try {
//             KeyPair keyPair = DHECCExample.generateECCKeyPair("secp256r1");
//             Client client = new Client("localhost", 8888, keyPair);
//             client.sendMessage("Hello, Server!");
//         } catch (Exception e) {
//             e.printStackTrace();
//         }
//     }
// }
