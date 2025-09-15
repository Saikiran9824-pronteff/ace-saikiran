package encrypt_decrypt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Encryption {
    // Function to encrypt a payload
    public static String encrypt(String payload, String publicKeyFilePath) {
        try {
            // Read the public key from file
            String publicKeyPem = new String(Files.readAllBytes(Paths.get(publicKeyFilePath)));

            // Remove the "BEGIN" and "END" lines and decode the PEM public key
            String publicKeyPEM = publicKeyPem.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // Create RSAKey instance from the public key
            RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey).build();

            // Create the JWE object
            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build(),
                    new Payload(payload));

            // Encrypt the JWE using the RSAKey
            jweObject.encrypt(new RSAEncrypter(rsaKey));

            // Serialize to compact form
            return jweObject.serialize();
        } catch (IOException e) {
            System.err.println("Error reading public key file: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error during encryption: " + e.getMessage());
        }
        return null; // Return null in case of error
    }

    public static void main(String[] args) {
        String publicKeyFilePath = "C:\\Users\\DELL\\Desktop\\INDUSKEYS\\IndusPublicKey.pem"; // Update with your public key path
        String payload = "{ \"panNumber\": \"FRHPD3158K\", \"uid\": \"448883321947\" }";

        String encrypted = encrypt(payload, publicKeyFilePath);
        if (encrypted != null) {
            System.out.println("Encrypted: " + encrypted);
        } else {
            System.out.println("Encryption failed.");
        }
    }
}
