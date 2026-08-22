package rs.ac.singidunum;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class DigitalSignature {
    public boolean verifySignature(PublicKey publicKey, byte[] signature, byte[] message) throws Exception {
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(publicKey);
            sign.update(message);
            return sign.verify(signature);
    }

    public byte[] generateSignature(PrivateKey privateKey, byte[] message) throws Exception{
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(privateKey);
            sign.update(message);
            return sign.sign();
    }

    public KeyPair pairOfKeys(int keySize) throws  NoSuchAlgorithmException {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize);
            return kpg.genKeyPair();
    }

    public void saveKey(byte[] key, String fileName) throws Exception{
            Files.write(Paths.get(fileName), key);
    }

    public PublicKey importPublicKey(byte[] encodedKey) throws Exception{
            X509EncodedKeySpec x509 = new X509EncodedKeySpec(encodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(x509);
        }

    public PrivateKey importPrivateKey(byte[] encodedKey) throws Exception {
        PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(pkcs8);
    }
}
