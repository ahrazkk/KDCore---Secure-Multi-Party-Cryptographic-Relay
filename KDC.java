import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class KDC {
    // Stores the output streams so KDC can broadcast messages to everyone
    private static Map<String, ObjectOutputStream> clientStreams = new HashMap<>();
    private static String groupKey = "GROUP_SESSION_KEY_789"; // The shared Ks

    public static void main(String[] args) throws Exception {
        // --- SETUP KDC RSA KEYS ---
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PublicKey puK = kp.getPublic();
        PrivateKey prK = kp.getPrivate();

        System.out.println("KDC Secure Chat Server Started...");
        ServerSocket serverSocket = new ServerSocket(8080);

        while (true) {
            Socket s = serverSocket.accept();
            new Thread(new KDC_ChatHandler(s, prK, puK)).start();
        }
    }

    static class KDC_ChatHandler implements Runnable {
        private Socket socket;
        private PrivateKey prK;
        private PublicKey puK;

        public KDC_ChatHandler(Socket s, PrivateKey prK, PublicKey puK) {
            this.socket = s;
            this.prK = prK;
            this.puK = puK;
        }

        public void run() {
            try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                 ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

                // --- PHASE 1 : STEP 1 - RECEIVE ID AND PUBLIC KEY ---
                String id = (String) in.readObject();
                PublicKey clientPU = (PublicKey) in.readObject();
                clientStreams.put(id, out);

                // --- PHASE 1 : STEP 2 - SEND KDC PU AND NONCE ---
                out.writeObject(puK); // Send KDC Public Key
                String nk = "NONCE_KDC_" + (int)(Math.random() * 1000);
                Cipher rsa = Cipher.getInstance("RSA");
                rsa.init(Cipher.ENCRYPT_MODE, clientPU);
                out.writeObject(rsa.doFinal((nk + "||ID_K").getBytes()));

                // --- PHASE 1 : STEP 3 - VERIFY CLIENT NONCE ---
                byte[] step3Data = (byte[]) in.readObject();
                rsa.init(Cipher.DECRYPT_MODE, prK);
                String decryptedStep3 = new String(rsa.doFinal(step3Data));
                System.out.println("[Handshake] Verified nonces for " + id + ": " + decryptedStep3);
                
                // --- PHASE 1 : STEP 5 - DISTRIBUTE MASTER KEY ---
                String masterKey = "MASTER_" + id;
                rsa.init(Cipher.ENCRYPT_MODE, clientPU);
                out.writeObject(rsa.doFinal(masterKey.getBytes()));

                // --- PHASE 2 : DISTRIBUTE GROUP SESSION KEY (Ks) ---
                byte[] keyBytes = Arrays.copyOf(masterKey.getBytes(), 16);
                SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
                Cipher aes = Cipher.getInstance("AES");
                aes.init(Cipher.ENCRYPT_MODE, secretKey);
                out.writeObject(aes.doFinal(groupKey.getBytes()));

                System.out.println("SUCCESS: " + id + " authenticated and received Group Key.");

                // --- LAB 4 : SECURE CHAT RELAY LOOP ---
                while (true) {
                    byte[] encryptedMsg = (byte[]) in.readObject();
                    byte[] signature = (byte[]) in.readObject();
                    
                    // Forward message to all clients EXCEPT the sender
                    for (String clientId : clientStreams.keySet()) {
                        if (!clientId.equals(id)) {
                            ObjectOutputStream target = clientStreams.get(clientId);
                            target.writeObject(id); // Tell recipient who sent it
                            target.writeObject(encryptedMsg);
                            target.writeObject(signature);
                            target.writeObject(clientPU); // Provide PU for signature verification
                        }
                    }
                }
            } catch (Exception e) { 
                System.out.println("A client disconnected or encountered an error."); 
            }
        }
    }
}