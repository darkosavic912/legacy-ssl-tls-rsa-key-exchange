package rs.ac.singidunum;

import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Client {
    private static final Logger LOGGER = Logger.getLogger(Client.class.getName());

    public static void main(String[] args)  {
        String serverName = "localhost";
        int port = 8088;
        System.out.println("Connecting to server " + serverName + ":" + port);
        try (Socket client = new Socket(serverName, port);
             DataOutputStream out = new DataOutputStream(client.getOutputStream());
             DataInputStream in = new DataInputStream(client.getInputStream())) {

            System.out.println("Connection established: " + client.getRemoteSocketAddress());

            //1. Alice sends username
            String message = "Alice";
            out.writeUTF(message);
            System.out.println("Client: " + message);

            //1.1  Client gets algorithm specification from server
            //     Client generates symmetric key according to the specification
            //     Client encrypts the symmetric key using server's public key
            String algSpec = in.readUTF();
            System.out.println("Server: " + algSpec);

            // Symmetric AES key (Secret key must be converted to byte array -> using getEncoded())
            SecretKey aesKey = null;
            if (algSpec.equals("AES/CBC/PKCS5")) {
                aesKey = new AES_cipher().generateKey("afaogq4654ybaoff0167!");
            }

            //1.2. Encrypting the symmetric AES key using RSA algorithm and server's public key
            RSA_encryption rsa = new RSA_encryption();
            PublicKey publicKey = rsa.importPublicKey(Files.readAllBytes
                    (Paths.get("server_public_RSA.key")));
            byte[] encryptedAesKey = rsa.rsaEncrypt(aesKey.getEncoded(), publicKey);

            //1.3. Digital signature of the encrypted AES key
            DigitalSignature digitalSignature = new DigitalSignature();
            PrivateKey privateKey = digitalSignature.importPrivateKey(Files.readAllBytes(
                    Path.of("client_private_DP.key")));
            byte[] encryptedKeySignature = digitalSignature.generateSignature(privateKey, encryptedAesKey);

            //1.4. Send encrypted AES key
            out.writeUTF(Base64.getEncoder().encodeToString(encryptedAesKey));

            //1.5. Send digital signature
            out.writeUTF(Base64.getEncoder().encodeToString(encryptedKeySignature));
            System.out.println("Digital signature: " + Arrays.toString(encryptedKeySignature));
            System.out.println("AES symmetric key: " + Arrays.toString(aesKey.getEncoded()));

            //2. Client decrypts the message received from the server (Confidentiality service)
            byte[] encryptedMessage = Base64.getDecoder().decode(in.readUTF());
            byte[] decryptedMessage = new AES_cipher().decrypt(aesKey, encryptedMessage);
            System.err.println("Message from server: ");
            System.out.println(new String(decryptedMessage));

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in client communication or cryptographic operations", e);
        }
        System.out.println("🔚 Connection closed.");
    }
}