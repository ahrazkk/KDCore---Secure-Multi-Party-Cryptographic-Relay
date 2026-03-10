import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class ClientC {
    private static String myID = "ID_C";
    private static long lastTimestamp = 0;

    public static void main(String[] args) throws Exception {
        // --- PHASE 1 : STEP 0 - SETUP CLIENT C RSA KEYS ---
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PublicKey myPU = kp.getPublic();
        PrivateKey myPR = kp.getPrivate();

        System.out.println("--- CLIENT C INITIALIZED ---");
        System.out.println("Public Key (PU_C): " + Base64.getEncoder().encodeToString(myPU.getEncoded()));
        System.out.println("Private Key (PR_C): " + Base64.getEncoder().encodeToString(myPR.getEncoded()));
        System.out.println("-----------------------------");

        Socket socket = new Socket("localhost", 8080);
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

        // --- PHASE 1 : STEP 1 - SEND IDENTITY AND PUBLIC KEY ---
        out.writeObject(myID);
        out.writeObject(myPU);

        // --- PHASE 1 : STEP 2 - RECEIVE KDC PUBLIC KEY AND NONCE ---
        PublicKey puK = (PublicKey) in.readObject();
        byte[] encryptedNK3 = (byte[]) in.readObject();
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, myPR);
        String nk3 = new String(rsa.doFinal(encryptedNK3)).split("\\|\\|")[0];

        // --- PHASE 1 : STEP 3 - SEND ENCRYPTED NONCES [NC || NK3] ---
        rsa.init(Cipher.ENCRYPT_MODE, puK); 
        out.writeObject(rsa.doFinal(("NC_CLIENT_C||" + nk3).getBytes()));

        // --- PHASE 1 : STEP 5 - RECEIVE AND DECRYPT MASTER KEY KC ---
        byte[] kcData = (byte[]) in.readObject();
        rsa.init(Cipher.DECRYPT_MODE, myPR);
        String kc = new String(rsa.doFinal(kcData));
        System.out.println("PHASE 1 SUCCESS: Established Master Key KC -> " + kc);

        // --- KEY FIX: Ensure Master Key is exactly 16 bytes for AES ---
        byte[] keyBytes = Arrays.copyOf(kc.getBytes(), 16); 
        SecretKeySpec masterKeySpec = new SecretKeySpec(keyBytes, "AES");

        // --- PHASE 2 : RECEIVE AND DECRYPT SESSION KEY KS (GROUP KEY) ---
        byte[] kabData = (byte[]) in.readObject();
        Cipher aes = Cipher.getInstance("AES");
        aes.init(Cipher.DECRYPT_MODE, masterKeySpec);
        String ks = new String(aes.doFinal(kabData));
        
        byte[] groupKeyBytes = Arrays.copyOf(ks.getBytes(), 16);
        SecretKeySpec groupKey = new SecretKeySpec(groupKeyBytes, "AES");
        System.out.println("PHASE 2 SUCCESS: Received Group Key Ks -> " + ks);

        // --- CHAT RECEIVE THREAD ---
        new Thread(() -> {
            try {
                while (true) {
                    String senderID = (String) in.readObject();
                    byte[] encMsg = (byte[]) in.readObject();
                    byte[] sig = (byte[]) in.readObject();
                    PublicKey senderPU = (PublicKey) in.readObject();

                    Cipher chatAes = Cipher.getInstance("AES");
                    chatAes.init(Cipher.DECRYPT_MODE, groupKey);
                    String decrypted = new String(chatAes.doFinal(encMsg));
                    String[] parts = decrypted.split("\\|\\|"); 
                    
                    long msgTime = Long.parseLong(parts[2]);
                    if (msgTime <= lastTimestamp) {
                        System.out.println("\n[!] SECURITY ALERT: Replay Attack Detected from " + senderID);
                        continue;
                    }
                    lastTimestamp = msgTime;

                    Signature verifySig = Signature.getInstance("SHA256withRSA");
                    verifySig.initVerify(senderPU);
                    verifySig.update((parts[0] + parts[1]).getBytes());
                    
                    if (verifySig.verify(sig)) {
                        System.out.println("\n[" + senderID + "]: " + parts[1]);
                    }
                }
            } catch (Exception e) {}
        }).start();

        // --- CHAT SEND LOOP ---
        Scanner sc = new Scanner(System.in);
        while (true) {
            String m = sc.nextLine();
            String timestamp = String.valueOf(System.currentTimeMillis());
            String dataToEncrypt = myID + "||" + m + "||" + timestamp;

            Cipher chatAes = Cipher.getInstance("AES");
            chatAes.init(Cipher.ENCRYPT_MODE, groupKey);
            byte[] encryptedData = chatAes.doFinal(dataToEncrypt.getBytes());

            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(myPR);
            sign.update((myID + m).getBytes());
            byte[] signature = sign.sign();

            out.writeObject(encryptedData);
            out.writeObject(signature);
        }
    }
}