package ECC;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class Client extends JFrame {
    private Socket client = null;
    private String serverAddr = "localhost";
    private int serverPort = 8888;
    private PrintWriter out;
    private BufferedReader in;
    private JTextField tf;
    private JTextArea ta;
    private JButton sendButton;
    private KeyPair keyPair;
    private PublicKey serverPublicKey;
    private Thread receiveThread;

    public Client() {
        tf = new JTextField(30);
        sendButton = new JButton("Send");
        sendButton.addActionListener(new SendButtonListener());
        ta = new JTextArea(10, 40);
        ta.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(ta);

        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout());
        panel.add(tf, BorderLayout.CENTER);
        panel.add(sendButton, BorderLayout.EAST);

        setLayout(new BorderLayout());
        add(panel, BorderLayout.SOUTH);
        add(scrollPane, BorderLayout.CENTER);

        setSize(500, 300);
        setLocationRelativeTo(null);
        this.setTitle("Client");
        setVisible(true);

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
            System.out.println("Kunci publik klien terkirim");

            startReceiveThread();
        } catch (IOException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            // e.printStackTrace();
        }
    }

    private void startReceiveThread() {
        receiveThread = new Thread(() -> {
            try {
                String message;
                while ((message = in.readLine()) != null) {
                    if (message.equalsIgnoreCase("quit")) {
                        break;
                    }
                    String encryptedMessage = message;
                    ta.append("Pesan dari server sebelum didekripsi: " + encryptedMessage + "\n");
                    String decryptedMessage = ECC.decrypt(encryptedMessage, keyPair.getPrivate());
                    ta.append("Pesan server (didekripsi): " + decryptedMessage + "\n");
                }
            } catch (Exception e) {
            }
        });
        receiveThread.start();
    }
    private class SendButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String message = tf.getText();
            System.out.println("Pesan asli: " + message);
            if (message.equalsIgnoreCase("quit")) {
                try {
                    out.println("quit");
                    client.close();
                } catch (IOException ioException) {
                }
                return;
            }
            try {
                byte[] encryptedMessage = ECC.encrypt(message, serverPublicKey);
                String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
                out.println(encodedMessage);
                ta.append("Pesan terenkripsi: " + encodedMessage + "\n");
            } catch (Exception exception) {
            }
            tf.setText("");
        }
    }

    public static void main(String[] args) {
        Client client = new Client();
        client.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
}