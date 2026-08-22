package rs.ac.singidunum;

import java.security.KeyPair;

public class GenerateKeys {
    public static void main(String[] args) throws Exception {
        DigitalSignature digitalSignature = new DigitalSignature();
        KeyPair ClientKeyPairDP = digitalSignature.pairOfKeys(2048);
        KeyPair ServerKeyPairDP = digitalSignature.pairOfKeys(2048);
        digitalSignature.saveKey(ClientKeyPairDP.getPrivate().getEncoded(), "client_private_DP.key");
        digitalSignature.saveKey(ClientKeyPairDP.getPublic().getEncoded(), "client_public_DP.key");
        digitalSignature.saveKey(ServerKeyPairDP.getPrivate().getEncoded(), "server_private_DP.key");
        digitalSignature.saveKey(ServerKeyPairDP.getPublic().getEncoded(), "server_public_DP.key");

        RSA_encryption rsaEncryption = new RSA_encryption();
        KeyPair ClientKeyPairRSA = rsaEncryption.pairOfKeys(2048);
        KeyPair ServerKeyPairRSA = rsaEncryption.pairOfKeys(2048);
        rsaEncryption.saveKey(ClientKeyPairRSA.getPrivate().getEncoded(), "client_private_RSA.key");
        rsaEncryption.saveKey(ClientKeyPairRSA.getPublic().getEncoded(), "client_public_RSA.key");
        rsaEncryption.saveKey(ServerKeyPairRSA.getPrivate().getEncoded(), "server_private_RSA.key");
        rsaEncryption.saveKey(ServerKeyPairRSA.getPublic().getEncoded(), "server_public_RSA.key");
    }
}

