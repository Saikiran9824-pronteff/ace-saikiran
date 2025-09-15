import java.io.FileReader;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class CipherUtils1 {
    static DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

    public static String signPayload(String xml) {
        try {
            Document doc = getDocument(xml);
            assert doc != null;
            signXmlReq(doc);
            return signedXmlRequest(doc);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    protected static Document getDocument(String rawRequest) {
        try {
            dbf.setNamespaceAware(true);
            dbf.setIgnoringElementContentWhitespace(true);
            return dbf.newDocumentBuilder().parse(new InputSource(new StringReader(rawRequest)));
        } catch (Exception e) {
            rawRequest = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>" + "<Response>" + rawRequest + "</Response>";
        }
        return null;
    }

    protected static void signXmlReq(Document doc) throws Exception {
        XMLSignatureFactory xmlSigFactory = XMLSignatureFactory.getInstance("DOM");

       PrivateKey privateKey = getPrivateKeyFromFile("/home/aceuser/generic/devssoprivatekey.pem");
     
        DOMSignContext domSignCtx = new DOMSignContext(privateKey, doc.getDocumentElement());

        Reference ref = xmlSigFactory.newReference(
                "",
                xmlSigFactory.newDigestMethod(DigestMethod.SHA256, null),
                Collections.singletonList(xmlSigFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
                null,
                null
        );

        SignedInfo signedInfo = xmlSigFactory.newSignedInfo(
                xmlSigFactory.newCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", (C14NMethodParameterSpec) null),
                xmlSigFactory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                Collections.singletonList(ref)
        );

        X509Certificate certificate = getCertificateFromFile("/home/aceuser/generic/pronteffcertsfn-sscert.pem");
      
        KeyInfoFactory keyInfoFact = xmlSigFactory.getKeyInfoFactory();
        KeyInfo keyInfo = keyInfoFact.newKeyInfo(Collections.singletonList(keyInfoFact.newKeyValue(certificate.getPublicKey())));

        XMLSignature xmlSignature = xmlSigFactory.newXMLSignature(signedInfo, keyInfo);
        xmlSignature.sign(domSignCtx);
    }

    public static String verifySign(String xml) {
        try {
            Document doc = getDocument(xml);
            NodeList nodeList = isXmlResponseSigned(doc);
            return checkXmlSignValidity(nodeList) ? "true" : "false";
        } catch (Exception e) {
        	
            e.printStackTrace();
        }
        return "false";
    }

    protected static NodeList isXmlResponseSigned(Document doc) throws Exception {
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("XML is not signed");
        }
        return nl;
    }

    protected static boolean checkXmlSignValidity(NodeList nodeList){
        boolean result = false;
    	 // DOMValidateContext valContext = new DOMValidateContext(getPublicKeyFromCertificate("/home/aceuser/generic/pronteffcertsfn-sscert.pem"), nodeList.item(0));
    
    	try{
    		
    		  DOMValidateContext valContext = new DOMValidateContext(getPublicKeyFromCertificate("/home/aceuser/generic/pronteffcertsfn-sscert.pem"), nodeList.item(0));
    		    

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);
        result= signature.validate(valContext);
    	}
    	catch(Exception e) {
    		e.printStackTrace();
    	}
    	return result;
    }

    protected static String signedXmlRequest(Document doc) throws Exception {
        TransformerFactory transFactory = TransformerFactory.newInstance();
        Transformer trans = transFactory.newTransformer();
        StringWriter writer = new StringWriter();
        trans.transform(new DOMSource(doc), new StreamResult(writer));
        return writer.toString();
    }

    public static PrivateKey getPrivateKeyFromFile(String privateKeyFile) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(privateKeyFile));
        String privateKeyPem = new String(keyBytes);
        privateKeyPem = privateKeyPem.replace("-----BEGIN PRIVATE KEY-----", "")
                                     .replace("-----END PRIVATE KEY-----", "")
                                     .replaceAll("\\s+", "");

        byte[] decodedKey = java.util.Base64.getDecoder().decode(privateKeyPem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

//    public static X509Certificate getCertificateFromFile(String certFilePath) throws Exception {
//        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
//        try (FileReader reader = new FileReader(certFilePath)) {
//            return (X509Certificate) certFactory.generateCertificate(Files.newInputStream(Paths.get(certFilePath)));
//        }
//    }
    
    public static X509Certificate getCertificateFromFile(String certFilePath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (InputStream fileInputStream = Files.newInputStream(Paths.get(certFilePath))) {
            return (X509Certificate) certFactory.generateCertificate(fileInputStream);
        }
    }

    public static PublicKey getPublicKeyFromCertificate(String certFilePath) throws Exception {
        X509Certificate cert = getCertificateFromFile(certFilePath);
        return cert.getPublicKey();
    }

    public static void main(String[] args) {
        String xmlToSign = "<Request><Data>Some data to be signed</Data></Request>";
        String signedXml = signPayload(xmlToSign);
        if (signedXml != null) {
            System.out.println("Signed XML: ");
            System.out.println(signedXml);
        } else {
            System.out.println("Signing failed.");
        }
        String verificationResult = verifySign(signedXml);
    	
        System.out.println("Signature verification result: " + verificationResult);
    }
}
