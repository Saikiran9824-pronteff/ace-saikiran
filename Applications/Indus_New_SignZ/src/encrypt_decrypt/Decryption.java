package encrypt_decrypt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Decryption {
    // Function to decrypt the JWE
    public static String decrypt(String encryptedJWResponse, String privateKeyFilePath) {
        try {
            // Read the private key from file
            String privateKeyPem = new String(Files.readAllBytes(Paths.get(privateKeyFilePath)));

            // Remove the "BEGIN" and "END" lines and decode the PEM private key
            String privateKeyPEM = privateKeyPem.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            // Parse the JWE
            JWEObject jweObject = JWEObject.parse(encryptedJWResponse);
            RSADecrypter decrypter = new RSADecrypter(privateKey);
            jweObject.decrypt(decrypter);

            // Get the decrypted payload
            return jweObject.getPayload().toString();
        } catch (IOException e) {
            System.err.println("Error reading private key file: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error during decryption: " + e.getMessage());
        }
        return null; // Return null in case of error
    }

    public static void main(String[] args) {
        String privateKeyFilePath = "C:\\Users\\DELL\\Desktop\\INDUSKEYS\\IndusPrivateKey.pem"; // Update with your private key path
        String encryptedJWResponse = "eeyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.GEtS5lDB_84Ryaw0aTbZ08CA7u-HNT1Bv2oEaY_GiZL3MUwNcfBfC7sWObuc-txjMMmvUM-XTQYrD2wkYg0YIaICGgEdlWsrL-DuePH02H0smaF3XlrDO2sgy3R-4lGh_yBVtJNKo90RdA0teZXpeS77WNUUo5lUBKOF4XzC1JBTp2w9azmqXPj2o8t8xShDemqPQ7fqVIP8YoMZ7COv5Km93T2d1HEuNWew3MIkDJ-3fSrTIe5lmesI6hVtPLgSVWWxF1dbsqwN-e_Nbx1E9pSmE3XVjd3zRKLMXabJEm4BXDOfa79ADIFUzC9HoNzvMQZZ2ZmdrFV93DZ2wmo-sQ.VtbWwmd_J4J9rhZp.1Pbzr2-tRj8YfaUv2ZZ62ssrsJy2k4IpncHeOr9KVShpjiJtwj_LFTsKwKGWhPDWe1Y9uGU2YJDyXJo7mmb0IDgDlHUBwkW6q0_8afzr08QiTfLRSEjRKWcFgMBuDb498ZOFuMzFfo_gW4DcUTQ2it2KgqVwk_7VZTtpuUgYUmn7HKsv3EDNUe7u2m9XE_rscEA.3mpa2W7GKi42op1HqlxFZw";

        String decrypted = decrypt(encryptedJWResponse, privateKeyFilePath);
        if (decrypted != null) {
            System.out.println("Decrypted: " + decrypted);
        } else {
            System.out.println("Decryption failed.");
        }
    }
}
