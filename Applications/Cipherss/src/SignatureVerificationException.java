
class SignatureVerificationException extends RuntimeException {    
	private final String message;    
	private final String errorCode;   
	public SignatureVerificationException(String message, String errorCode) {   
		super(message); 
		System.out.print(message);
		this.message = message;      
				this.errorCode = errorCode; 
				}}