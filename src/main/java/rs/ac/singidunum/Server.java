package rs.ac.singidunum;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Server {
    private static final Logger LOGGER = Logger.getLogger(Server.class.getName());

    public static void main(String[] args) {
        int port = 8088;
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started. Waiting for client...");

            while (true) {

                try (Socket server = serverSocket.accept();
                     DataInputStream in = new DataInputStream(server.getInputStream());
                     DataOutputStream out = new DataOutputStream(server.getOutputStream())) {

                    System.out.println("Client connected: " + server.getRemoteSocketAddress());

                    //1. Server accepts the user, authentication and confidentiality service
                    String clientMessage = in.readUTF();
                    System.out.println("Client: " + clientMessage);

                    //1.1. Server sends algorithm specification to the client
                    String algSpec = "AES/CBC/PKCS5";
                    out.writeUTF(algSpec);

                    //1.2. Server authenticates client, then decrypts symmetric AES key
                    byte[] encryptedAesKey = Base64.getDecoder().decode(in.readUTF());

                    //1.3. Receive digital signature of the encrypted key
                    byte[] keyDigitalSignature = Base64.getDecoder().decode(in.readUTF());
                    System.out.println("Digital signature of encrypted key: " + Arrays.toString(keyDigitalSignature));

                    AES_cipher aesCipher = new AES_cipher();
                    DigitalSignature digitalSignature = new DigitalSignature();
                    SecretKey aesKey = null;

                    //1.4. Fetching public key of the client (used for signature verification)
                    PublicKey publicKey = digitalSignature.importPublicKey(Files.readAllBytes
                            (Path.of("client_public_DP.key")));

                    //1.5. Verification of digital signature
                    if (digitalSignature.verifySignature(publicKey, keyDigitalSignature, encryptedAesKey)) {
                        System.out.println("Client: " + clientMessage + " has been successfully authenticated");

                        //1.6. Extracting the AES key using RSA decryption
                        RSA_encryption rsa = new RSA_encryption();
                        PrivateKey privateKey = rsa.importPrivateKey(Files.readAllBytes
                                (Path.of("server_private_RSA.key")));
                        aesKey = new SecretKeySpec(rsa.rsaDecrypt(encryptedAesKey, privateKey), "AES");
                    } else {
                        System.out.println("Error generating AES key");
                        continue;
                    }

                    //2. Sending the first message encrypted with AES algorithm
                    String message2 = "Alice, this is the first message sent with hybrid cryptography using RSA and AES!";
                    byte[] encryptedMessage = aesCipher.encrypt(aesKey, message2.getBytes());
                    out.writeUTF(Base64.getEncoder().encodeToString(encryptedMessage));
                    System.out.println("Message encrypted with AES sent to the client!!");

                    System.out.println("Connection closed.\n");
                } catch (Exception e) {
                    // Communication failure with ONE client does not crash the server
                    LOGGER.log(Level.WARNING, "Error processing client connection", e);
                }
            }
        } catch (Exception e) {
            // Failure of ServerSocket itself (e.g., port 8088 is occupied)
            LOGGER.log(Level.SEVERE, "Critical error: Server failed to start", e);
        }
    }
}