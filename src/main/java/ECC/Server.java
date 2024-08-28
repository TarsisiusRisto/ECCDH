package ECC;

import java.awt.BorderLayout;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class Server extends JFrame {
    private static final String[] CURVE_OPTIONS = {"secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1"}; 
    private final JTextArea messageArea;
    private final JTextField messageField;
    private final JButton sendButton;
    private PublicKey serverPublicKey;
    private PrivateKey serverPrivateKey;
    private String chosenCurve;
    private Handler currentHandler;
    private final JTextField latencyField;

    public Server() {
        super("ECC Server");
        JPanel topPanel = new JPanel(new BorderLayout());
        messageArea = new JTextArea();
        messageArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(messageArea);
        topPanel.add(scrollPane, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel();
        messageField = new JTextField(30);
        sendButton = new JButton("Send");
        sendButton.addActionListener(e -> sendMessage());
        bottomPanel.add(messageField);
        bottomPanel.add(sendButton);

        latencyField = new JTextField();
        latencyField.setEditable(false);
        topPanel.add(latencyField, BorderLayout.SOUTH);

        getContentPane().add(topPanel, BorderLayout.CENTER);
        getContentPane().add(bottomPanel, BorderLayout.SOUTH);

        setLocationRelativeTo(null);
        setSize(500, 300);
        setVisible(true);

        chooseCurve();
    }

    private void chooseCurve() {
        chosenCurve = (String) JOptionPane.showInputDialog(
                this,
                "Pilih kurva:",
                "Kurva ECC",
                JOptionPane.PLAIN_MESSAGE,
                null,
                CURVE_OPTIONS,
                CURVE_OPTIONS[0]);
    
        if (chosenCurve == null) {
            JOptionPane.showMessageDialog(this, "Kurva tidak dipilih, menggunakan secp256r1 secara default");
            chosenCurve = "secp256r1";
        }
        messageArea.append("Kurva yang dipilih: " + chosenCurve + "\n");
        
        generateKeyPair();
        startServer();
    }

    private void generateKeyPair() {
        try {
            KeyPair keyPair = ECC.generateKeyPair(chosenCurve);
            serverPublicKey = keyPair.getPublic();
            serverPrivateKey = keyPair.getPrivate();
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            System.exit(1);
        }
    }

    private void startServer() {
        new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(8888)) {
                System.out.println("Server dimulai pada port 8888");
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("Klien terhubung: " + clientSocket.getInetAddress());
                    currentHandler = new Handler(clientSocket, serverPublicKey, serverPrivateKey);
                    currentHandler.start();
                }
            } catch (Exception e) {
            }
        }).start();
    }

    private class Handler extends Thread {
        private final Socket clientSocket;
        private final PublicKey serverPublicKey;
        private final PrivateKey serverPrivateKey;
        private PublicKey clientPublicKey;
        private PrintWriter out;
        private BufferedReader in;
        long startTime = System.currentTimeMillis();

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
                if (clientPublicKeyStr != null) {
                    byte[] clientPublicKeyBytes = Base64.getDecoder().decode(clientPublicKeyStr);
                    clientPublicKey = KeyFactory.getInstance("EC", "BC").generatePublic(new X509EncodedKeySpec(clientPublicKeyBytes));

                    new Thread(() -> {
                        try {
                            String message;
                            while ((message = in.readLine()) != null) {
                                if (message.equalsIgnoreCase("quit")) {
                                    break;
                                }
                                resetStartTime();
                                messageArea.append("Pesan Klien: " + message + "\n");
                                String decryptedMessage = ECC.decrypt(message, serverPrivateKey);
                                messageArea.append("Pesan Klien (didekripsi): " + decryptedMessage + "\n");
                                long endTime = System.currentTimeMillis();
                                double latency = endTime - startTime;
                                latencyField.setText("Latency: " + latency + "ms");
                            }
                        } catch (Exception e) {
                        } finally {
                            try {
                                clientSocket.close();
                            } catch (IOException e) {
                            }
                        }
                    }).start();
                }
            } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            }
        }

        public void resetStartTime() {
            startTime = System.currentTimeMillis();
        }

        public void sendMessage(String message) {
            try {
                if (clientPublicKey != null) {
                    byte[] encryptedMessage = ECC.encrypt(message, clientPublicKey);
                    String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
                    out.println(encodedMessage);
                    messageArea.append("Pesan terenkripsi: " + encodedMessage + "\n");
                }
            } catch (Exception e) {
            }
        }
    }

    private void sendMessage() {
        String message = messageField.getText().trim();
        System.out.println("Pesan asli : " + message);
        if (!message.isEmpty() && currentHandler != null) {
            currentHandler.sendMessage(message);
            messageField.setText("");
            messageField.requestFocus();
        }
    }

    public static void main(String[] args) {
        Server server = new Server();
        server.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
}