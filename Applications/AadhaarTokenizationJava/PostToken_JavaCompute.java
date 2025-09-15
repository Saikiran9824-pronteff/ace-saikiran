import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.ibm.broker.plugin.MbUserException;

public class PostToken_JavaCompute extends MbJavaComputeNode {

	public void evaluate(MbMessageAssembly inAssembly) throws MbException {
		MbOutputTerminal out = getOutputTerminal("out");
		MbOutputTerminal alt = getOutputTerminal("alternate");

		MbMessage inMessage = inAssembly.getMessage();
		MbMessageAssembly outAssembly = null;
		try {
			// create new message as a copy of the input
			MbMessage outMessage = new MbMessage(inMessage);
			outAssembly = new MbMessageAssembly(inAssembly, outMessage);
			// ----------------------------------------------------------
			// Add user code below
			
	//Encryption code

			String inputdata1="<TokenizeData id=\""+outAssembly.getGlobalEnvironment().getRootElement().getFirstElementByPath("aadhaarNo").getValueAsString()+"\"></TokenizeData>";			
			byte[] inputData = inputdata1.getBytes();
			byte[] sessionKey = null;
			Date date = Calendar.getInstance().getTime();  
			DateFormat dateFormat = new SimpleDateFormat("yyyy-mm-dd hh:mm:ss");  
			String val1 = dateFormat.format(date);  			
			byte[] cipherTextWithTS = null ;
			byte[] iv = null;
			byte[] aad = null;
			byte[] encSrcHash = null ;
			//String	certficatePath =  outAssembly.getGlobalEnvironment().getRootElement().getFirstElementByPath("certificatePath").getValueAsString();
			String	certficatePath = "/home/aceuser/generic/UIDAI-EncryptionKey-Pre-Production.crt";
			MbElement root=outAssembly.getGlobalEnvironment().getRootElement();

			try {
				// session key generation ------------------------------
				sessionKey = generateSessionKey();
				
				// pid block encryption
				iv = generateIv(val1);
				aad = generateAad(val1);	
				cipherTextWithTS = encrypt(inputData, sessionKey, val1);
				// hmac
				byte[] srcHash = generateHash(inputData);
				encSrcHash = encryptDecryptUsingSessionKey(true, sessionKey, iv, aad, srcHash);
			  byte[] decryptedText = decrypt(cipherTextWithTS, sessionKey, encSrcHash);
			  root.createElementAsLastChild(MbElement.TYPE_NAME, "cipherTextWithTS",new String(cipherTextWithTS,"ISO_8859_1") );

			  root.createElementAsLastChild(MbElement.TYPE_NAME, "decryptedText",new String(decryptedText,"ISO_8859_1") );

			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalStateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidCipherTextException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
			
			
			byte[] encryptedSessionKey=null;
			
			try {
				if (pubKey != null ) {
				
					
				} else {
					InputStream in = new FileInputStream(certficatePath);
					CertificateFactory f = CertificateFactory.getInstance("X.509");
					Certificate certificate = f.generateCertificate(in);
					//PublicKey pubKey = certificate.getPublicKey();
					pubKey = certificate.getPublicKey();
				}
				
						// encrypting session key using RSA
				
				Cipher cipher;	
				cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.ENCRYPT_MODE, pubKey);
				encryptedSessionKey = cipher.doFinal(sessionKey);
			
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
				


	//End of Encryption code		
			

root.createElementAsLastChild(MbElement.TYPE_NAME, "Skey",new String(Base64.getEncoder().encodeToString(encryptedSessionKey)));
root.createElementAsLastChild(MbElement.TYPE_NAME, "Hmac",new String(Base64.getEncoder().encodeToString(encSrcHash)));
root.createElementAsLastChild(MbElement.TYPE_NAME, "Data",new String(Base64.getEncoder().encodeToString(cipherTextWithTS)));

			

			// End of user code
			// ----------------------------------------------------------
		} catch (MbException e) {
			// Re-throw to allow Broker handling of MbException
			throw e;
		} catch (RuntimeException e) {
			// Re-throw to allow Broker handling of RuntimeException
			throw e;
		} catch (Exception e) {
			// Consider replacing Exception with type(s) thrown by user code
			// Example handling ensures all exceptions are re-thrown to be handled in the flow
			throw new MbUserException(this, "evaluate()", "", "", e.toString(), null);
		}
		// The following should only be changed
		// if not propagating message to the 'out' terminal
		out.propagate(outAssembly);

	}

	/**
	 * onPreSetupValidation() is called during the construction of the node
	 * to allow the node configuration to be validated.  Updating the node
	 * configuration or connecting to external resources should be avoided.
	 *
	 * @throws MbException
	 */
	@Override
	public void onPreSetupValidation() throws MbException {
	}

	/**
	 * onSetup() is called during the start of the message flow allowing
	 * configuration to be read/cached, and endpoints to be registered.
	 *
	 * Calling getPolicy() within this method to retrieve a policy links this
	 * node to the policy. If the policy is subsequently redeployed the message
	 * flow will be torn down and reinitialized to it's state prior to the policy
	 * redeploy.
	 *
	 * @throws MbException
	 */
	@Override
	public void onSetup() throws MbException {
	}

	/**
	 * onStart() is called as the message flow is started. The thread pool for
	 * the message flow is running when this method is invoked.
	 *
	 * @throws MbException
	 */
	@Override
	public void onStart() throws MbException {
	}

	/**
	 * onStop() is called as the message flow is stopped. 
	 *
	 * The onStop method is called twice as a message flow is stopped. Initially
	 * with a 'wait' value of false and subsequently with a 'wait' value of true.
	 * Blocking operations should be avoided during the initial call. All thread
	 * pools and external connections should be stopped by the completion of the
	 * second call.
	 *
	 * @throws MbException
	 */
	@Override
	public void onStop(boolean wait) throws MbException {
	}

	/**
	 * onTearDown() is called to allow any cached data to be released and any
	 * endpoints to be deregistered.
	 *
	 * @throws MbException
	 */
	@Override
	public void onTearDown() throws MbException {
	}
	
	//Encryption methods
	
	// AES Key size - in bits
	public static final int AES_KEY_SIZE_BITS = 256; 	
	
	// IV length - last 96 bits of ISO format timestamp
	public static final int IV_SIZE_BITS = 96;  

	// Additional authentication data - last 128 bits of ISO format timestamp 
	public static final int AAD_SIZE_BITS = 128; 

	// Authentication tag length - in bits
	public static final int AUTH_TAG_SIZE_BITS = 128; 

	private static final String JCE_PROVIDER = "BC";

	// Hashing Algorithm Used for encryption and decryption
	private static String algorithm = "SHA-256";

	// SHA-256 Implementation provider	 
	private final static String SECURITY_PROVIDER = "BC";

	// Default Size of the HMAC/Hash Value in bytes
	 
	private static int HMAC_SIZE = 32;
	static{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	private static PublicKey pubKey;
	/**
	 * Creates a AES key that can be used as session key (skey)
	 * @return session key byte array 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static byte[] generateSessionKey() throws NoSuchAlgorithmException, NoSuchProviderException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		KeyGenerator kgen = KeyGenerator.getInstance("AES",JCE_PROVIDER);
		kgen.init(AES_KEY_SIZE_BITS);
		SecretKey key = kgen.generateKey();
		byte[] symmKey = key.getEncoded();
		return symmKey;
	}


	/**
	 * Fetch specified last bits from String
	 * @param ts - timestamp string 
	 * @param bits - no of bits to fetch
	 * @return byte array of specified length
	 * @throws UnsupportedEncodingException
	 */
	public static byte[] getLastBits(String ts, int bits) throws UnsupportedEncodingException {
		byte[] tsInBytes = ts.getBytes("UTF-8");
		return Arrays.copyOfRange(tsInBytes, tsInBytes.length - bits, tsInBytes.length);
	}

	/**
	 * Get current ISO time 
	 * @return current time in String
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static String getCurrentISOTimeInUTF8() {
		SimpleDateFormat df = new SimpleDateFormat("YYYY-MM-DD'T'hh:mm:ss"); 
		String timeNow = df.format(new Date());
		return timeNow;
	}

	/**
	 * Generate IV using timestamp 
	 * @param ts - timestamp string
	 * @return 12 bytes array
	 * @throws UnsupportedEncodingException
	 */
	public static byte[] generateIv(String ts) throws UnsupportedEncodingException {
		return getLastBits(ts, IV_SIZE_BITS / 8);
	}


	/**
	 * Generate AAD using timestamp
	 * @param ts - timestamp string
	 * @return 16 bytes array
	 * @throws UnsupportedEncodingException
	 */
	public static byte[] generateAad(String ts) throws UnsupportedEncodingException {
		return getLastBits(ts, AAD_SIZE_BITS / 8);
	}

	/**
	 * Convert byte array to hex string
	 * @param bytes - input bytes
	 * @return - hex string
	 */
	public static String byteArrayToHexString(byte[] bytes) {
		StringBuffer result = new StringBuffer();
		for (int i = 0; i < bytes.length; i++) {
			result.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return result.toString();
	}

	/**
	 * Returns the 256 bit hash value of the message
	 * 
	 * @param message
	 *            full plain text
	 * 
	 * @return hash value
	 * @throws HashingException
	 * @throws HashingException
	 *             I/O errors
	 */
	public static byte[] generateHash(byte[] message) throws Exception {
		byte[] hash = null;
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			MessageDigest digest = MessageDigest.getInstance(algorithm,SECURITY_PROVIDER);
			digest.reset();
			HMAC_SIZE = digest.getDigestLength();
			hash = digest.digest(message);
		} catch (GeneralSecurityException e) {
			throw new Exception(
					"SHA-256 Hashing algorithm not available");
		}
		return hash;
	}

	/**
	 * Returns true / false value based on Hash comparison between source and generated 
	 * @param srcHash
	 * @param plainTextWithTS
	 * @return hash value
	 * @throws Exception
	 */
	private static boolean validateHash(byte[] srcHash, byte[] plainTextWithTS) throws Exception {
		byte[] actualHash = generateHash(plainTextWithTS);
		//System.out.println("Hash of actual plain text in cipher hex:--->"+byteArrayToHexString(actualHash));
//			boolean tr =  Arrays.equals(srcHash, actualHash);
		if (new String(srcHash, "UTF-8").equals(new String(actualHash, "UTF-8"))) {
			return true;
		} else {
			return false;
		}
	}


	/**
	 * Convert hex string to byte array
	 * @param data  - input hex string
	 * @return byte array
	 */
	private static byte[] hexStringToByteArray(String data) {
		int k = 0;
		byte[] results = new byte[data.length() / 2];
		for (int i = 0; i < data.length();) {
			results[k] = (byte) (Character.digit(data.charAt(i++), 16) << 4);
			results[k] += (byte) (Character.digit(data.charAt(i++), 16));
			k++;
		}
		return results;
	}

	/**
	 * Encrypts given data using session key, iv, aad
	 * @param cipherOperation - true for encrypt, false otherwise
	 * @param skey	- Session key
	 * @param iv  	- initialization vector or nonce
	 * @param aad 	- additional authenticated data
	 * @param data 	- data to encrypt
	 * @return encrypted data
	 * @throws IllegalStateException
	 * @throws InvalidCipherTextException
	 */
	public static byte[] encryptDecryptUsingSessionKey(boolean cipherOperation, byte[] skey, byte[] iv, byte[] aad,
			byte[] data) throws IllegalStateException, InvalidCipherTextException {
		
		//System.out.println("--in AESCipher encryptDecryptUsingSessionKey cipherOperation:"+cipherOperation);
		//System.out.println("--in AESCipher encryptDecryptUsingSessionKey skey:"+skey);
		//System.out.println("--in AESCipher encryptDecryptUsingSessionKey iv:"+iv);
		//System.out.println("--in AESCipher encryptDecryptUsingSessionKey aad:"+aad);
		//System.out.println("--in AESCipher encryptDecryptUsingSessionKey data:"+data);
		
		AEADParameters aeadParam = new AEADParameters(new KeyParameter(skey), AUTH_TAG_SIZE_BITS, iv, aad);
		GCMBlockCipher gcmb = new GCMBlockCipher(new AESEngine());

		gcmb.init(cipherOperation, aeadParam);
		
		
		int outputSize = gcmb.getOutputSize(data.length);
//		System.out.println("--in AESCipher encryptDecryptUsingSessionKey outputSize:"+outputSize);
		
		byte[] result = new byte[outputSize];
		//System.out.println("--in AESCipher encryptDecryptUsingSessionKey result:"+result);
		
		int processLen = gcmb.processBytes(data, 0, data.length, result, 0);
		//System.out.println("--in AESCipher encryptDecryptUsingSessionKey processLen:"+processLen);
		
		gcmb.doFinal(result, processLen);

		return result;
	}

	/**
	 * Encrypts given data using a generated session and used ts as for all other needs.
	 * @param inputData - data to encrypt
	 * @param sessionKey  - Session key
	 * @param ts - timestamp as per the PID
	 * @return encrypted data
	 * @throws IllegalStateException
	 * @throws InvalidCipherTextException
	 * @throws Exception 
	 */    
	public static byte[] encrypt(byte[] inputData, byte[] sessionKey, String ts) throws IllegalStateException, InvalidCipherTextException, Exception {
	    byte[] iv = generateIv(ts);
	    byte[] aad = generateAad(ts);
	    byte[] cipherText = encryptDecryptUsingSessionKey(true, sessionKey, iv, aad, inputData);
	    byte[] tsInBytes = ts.getBytes("UTF-8");
	    byte [] packedCipherData = new byte[cipherText.length + tsInBytes.length];   
		System.arraycopy(tsInBytes, 0, packedCipherData, 0, tsInBytes.length);
		System.arraycopy(cipherText, 0, packedCipherData, tsInBytes.length, cipherText.length);
		return packedCipherData;
	}

	/**
	 * Decrypts given input data using a sessionKey.
	 * @param inputData - data to decrypt
	 * @param sessionKey  - Session key
	 * @return decrypted data
	 * @throws IllegalStateException
	 * @throws InvalidCipherTextException
	 * @throws Exception 
	 */ 
	public static byte[] decrypt(byte[] inputData, byte[] sessionKey, byte[] encSrcHash) throws IllegalStateException, InvalidCipherTextException, Exception {
		byte[] bytesTs = Arrays.copyOfRange(inputData, 0, 19);
		String ts = new String(bytesTs);
		byte[] cipherData = Arrays.copyOfRange(inputData, bytesTs.length, inputData.length);
	    byte[] iv = generateIv(ts);
	    byte[] aad = generateAad(ts);
	    
	    //System.out.println("in AESCipher decrypt sessionKey:"+sessionKey);
	    //System.out.println("in AESCipher decrypt iv:"+iv);
	    //System.out.println("in AESCipher decrypt aad:"+aad);
	    //System.out.println("in AESCipher decrypt cipherData:"+cipherData);
	    byte[] plainText = encryptDecryptUsingSessionKey(false, sessionKey, iv, aad, cipherData);
	    byte[] srcHash = encryptDecryptUsingSessionKey(false, sessionKey, iv, aad, encSrcHash);
	    System.out.println("Decrypted HAsh in cipher text: "+byteArrayToHexString(srcHash));
	    boolean result = validateHash(srcHash, plainText);
	    if(!result){
	    	throw new Exception( "Integrity Validation Failed : " + "The original data at client side and the decrypted data at server side is not identical");
	    } else{
	    	//System.out.println("Hash Validation is Successful!!!!!");
	    	return plainText;
	    }
	}

	private static final char[] kHexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
	    'E', 'F'};
	public static byte[] encryptData(byte[] data, byte[] sessionKey){
	        byte[] encryptedData = null;
	        try {
	                SecretKeySpec secretKey = new SecretKeySpec(sessionKey, "AES");

	                Cipher aesCipher;
	                aesCipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
	                //aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
	                aesCipher.init(Cipher.ENCRYPT_MODE, secretKey );
	                encryptedData=aesCipher.doFinal(data);

	        } catch (NoSuchAlgorithmException e) {

	                //e.printStackTrace();
	        } catch (NoSuchPaddingException e) {

	                //e.printStackTrace();
	        } catch (InvalidKeyException e) {

	                //e.printStackTrace();
	        } catch (IllegalBlockSizeException e) {

	                //e.printStackTrace();
	        } catch (BadPaddingException e) {

	                //e.printStackTrace();
	        }
	        return encryptedData;
	}

		
	 public static String bufferToHex(byte[] buffer, int startOffset, int length) {
	     StringBuffer hexString = new StringBuffer(2 * length);
	     int endOffset = startOffset + length;

	     for (int i = startOffset; i < endOffset; i++) {
	         appendHexPair(buffer[i], hexString);
	     }

	     return hexString.toString();
	 }
	 private static void appendHexPair(byte b, StringBuffer hexString) {
	     char highNibble = kHexChars[(b & 0xF0) >> 4];
	     char lowNibble = kHexChars[b & 0x0F];

	     hexString.append(highNibble);
	     hexString.append(lowNibble);
	 }
	 private static String leftPad(String str, int len, char padChar)
	 {
	         int strLen = str.length();
	         if(strLen > len)
	                 return str;
	         while (str.length()!=len)
	         {
	                 str = padChar+str;
	         }
	         return str;
	 }
	 private static String convertHexToAscii(String hex)
	 {
	         StringBuilder sb = new StringBuilder();

	         if(hex!=null)
	         {
	                 //49204c6f7665204a617661 split into two characters 49, 20, 4c...
	                 for( int i=0; i<hex.length()-1; i+=2){
	                 //grab the hex in pairs
	                 String output = hex.substring(i, (i + 2));
	                 //convert hex to decimal
	                 int decimal = Integer.parseInt(output,16);
	                 //convert the decimal to character
	                         sb.append((char)decimal);
	                 }
	         }
	         return sb.toString();
	 }
	 private static String convertStringToHex(String str){

	           char[] chars = str.toCharArray();

	           StringBuffer hex = new StringBuffer();
	           for(int i = 0; i < chars.length; i++){
	             hex.append(leftPad(Integer.toHexString((int)chars[i]),2,'0'));
	           }

	           return hex.toString(); 
	   }

	
	//End of encryption
}



