package ECCwithoutGUI;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Client {
    private Socket client = null;
    private String serverAddr = "localhost";
    private int serverPort = 8888;
    private PrintWriter out;
    private BufferedReader in;
    private KeyPair keyPair;
    private PublicKey serverPublicKey;
    private long lastSendTime;

    public Client() {
        try {
            client = new Socket(serverAddr, serverPort);
            out = new PrintWriter(client.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(client.getInputStream()));

            String selectedCurve = in.readLine();
            keyPair = ECC.generateKeyPair(selectedCurve);
            String serverPublicKeyStr = in.readLine();
            byte[] serverPublicKeyBytes = Base64.getDecoder().decode(serverPublicKeyStr);
            serverPublicKey = KeyFactory.getInstance("EC", "BC").generatePublic(new X509EncodedKeySpec(serverPublicKeyBytes));

            String publicKeyStr = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            out.println(publicKeyStr);
            System.out.println("Public key sent to server.");

            startReceiveThread();

            Scanner scanner = new Scanner(System.in);
            while (true) {
                System.out.print("Enter Message: ");
                String message = scanner.nextLine();
                if (message.equalsIgnoreCase("quit")) {
                    out.println("quit");
                    client.close();
                    break;
                }
                sendMessage(message);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void startReceiveThread() {
        new Thread(() -> {
            try {
                String message;
                while ((message = in.readLine()) != null) {
                    if (message.equalsIgnoreCase("quit")) {
                        break;
                    }
    
                    long receiveTime = System.currentTimeMillis();
                    String decryptedMessage = ECC.decrypt(message, keyPair.getPrivate());
    
                    System.out.println("\nServer (before decryption): " + message);
                    System.out.println("Server: " + decryptedMessage);
    
                    long latency = receiveTime - lastSendTime;
                    System.out.println("Latency: " + latency + " ms");
                    System.out.print("Enter Message: ");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }
    
    public void sendMessage(String message) {
        try {
            lastSendTime = System.currentTimeMillis();
            byte[] encryptedMessage = ECC.encrypt(message, serverPublicKey);
            String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
    
            System.out.println("Client (before encryption): " + message);
            System.out.println("Client (encrypted): " + encodedMessage);
    
            out.println(encodedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new Client();
    }
}