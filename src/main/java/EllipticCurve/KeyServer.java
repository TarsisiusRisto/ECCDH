package EllipticCurve;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

public class KeyServer {
    private static final int PORT = 9999;
    private static final Map<String, String> keyStore = new HashMap<>();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("KeyServer started on port " + PORT);

            while (true) {
                new KeyServerHandler(serverSocket.accept()).start();
            }
        } catch (IOException e) {
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
                    String publicKey = in.readLine();
                    keyStore.put(clientID, publicKey);
                    out.println("Public key stored successfully.");
                    System.out.println("Stored public key for ID: " + clientID + " - " + publicKey);
                } else if (request.startsWith("RETRIEVE")) {
                    String clientID = request.split(" ")[1];
                    String publicKey = keyStore.getOrDefault(clientID, "Key not found for ID: " + clientID);
                    out.println(publicKey);
                    System.out.println("Retrieved public key for ID: " + clientID + " - " + publicKey);
                } else {
                    out.println("Invalid request");
                }
            } catch (IOException e) {
            }
        }
    }
}
