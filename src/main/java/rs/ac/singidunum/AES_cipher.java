package rs.ac.singidunum;

import java.security.*;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES_cipher {

    public byte[] encrypt(SecretKey key, byte[] plaintext)  throws  Exception{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashKey = md.digest(key.getEncoded());
            byte[] iv = Arrays.copyOfRange(hashKey, 0, 16);
            IvParameterSpec IV = new IvParameterSpec(iv);
            //E
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key, IV);
            byte[] sifrat = c.doFinal(plaintext);
            return sifrat;
    }

    public byte[] decrypt(SecretKey key, byte[] ciphertext) throws Exception{
            //IV
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashKey = md.digest(key.getEncoded());
            byte[] iv = Arrays.copyOfRange(hashKey, 0, 16);
            IvParameterSpec IV = new IvParameterSpec(iv);
            //E
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, key, IV);
            byte[] plaitext = c.doFinal(ciphertext);
            return plaitext;
    }

    public SecretKey generateKey(String password) throws NoSuchAlgorithmException{
            SecretKey key;
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte []hash = md.digest(password.getBytes());
            key = new SecretKeySpec(Arrays.copyOfRange(hash, 0, 16),"AES");
            return key;
    }
}
