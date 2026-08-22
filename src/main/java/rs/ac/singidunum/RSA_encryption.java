package rs.ac.singidunum;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class RSA_encryption {
    public KeyPair pairOfKeys(int keySize) throws NoSuchAlgorithmException{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize);
            return kpg.genKeyPair();
    }
    
    public byte [] rsaEncrypt(byte [] message, PublicKey publicKey) throws Exception{
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(Cipher.ENCRYPT_MODE, publicKey);
            return c.doFinal(message);
    }
    
    public byte [] rsaDecrypt(byte [] ciphertext, PrivateKey privateKey) throws Exception{
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(Cipher.DECRYPT_MODE, privateKey);
            return c.doFinal(ciphertext);
    }
    
    public void saveKey(byte [] key, String fileName) throws IOException{
            Files.write(Paths.get(fileName), key);
    }
    
    public PublicKey importPublicKey(byte [] encodedKey) throws Exception{
            X509EncodedKeySpec x509 = new X509EncodedKeySpec(encodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(x509);
    }
    
    public PrivateKey importPrivateKey(byte [] encodedKey) throws Exception{
            PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(encodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(pkcs8);
    }
}
