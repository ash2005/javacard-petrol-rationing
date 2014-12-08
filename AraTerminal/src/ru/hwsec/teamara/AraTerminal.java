package ru.hwsec.teamara;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import java.util.Scanner;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;


public class AraTerminal {

    protected final boolean debug = false;
	protected CardComm cardComm;

	public static final short MONTHLY_ALLOWANCE = 200;
	
	private byte[] cardEncKey;
    private byte[] cardMacKey;
    private byte[] cardIV;
    private byte[] terminalEncKey;
    private byte[] terminalMacKey;
    private byte[] terminalIV;
    
    protected byte[] cardKeyBytes;
    
    protected byte termID;
    protected byte type;
    
    /*
     * Constructor, gets the termID as an argument.
     */
    
    public AraTerminal(byte termID, byte type) {
    	this.termID = termID;
    	this.type = type;
    	try {
			cardComm = new CardComm();
		} catch (CardException e) {
			System.out.println("Could not connect to the card or simulator.");
			System.exit(1);
		}
		System.out.println("Connected to the smart card.");
    }
    
    protected void connectToCard() {
        try {
			this.performHandshake();
			this.checkPIN();
		} catch (CardException e) {
			System.out.println("In AraTerminal.execute an error occured when communicating with the card");
		} catch (GeneralSecurityException e) {
			System.out.println("In AraTerminal.execute a crypto error occured");
		}
    }
    
    public void disconnectFromCard() {
    	this.cardComm.close();
    }

    /* Mutual Authentication Functions */

    private boolean performHandshake() throws CardException, GeneralSecurityException {
        ResponseAPDU resp;
        // We first generate 4 random bytes to send the card
        Random rnd = new Random(Calendar.getInstance().getTimeInMillis());
        byte[] termRndBytes = new byte[4];
        rnd.nextBytes(termRndBytes);

        // Send TERMINAL_HELLO and get back the CARD_HELLO answer containing 4 random bytes
        resp = this.cardComm.sendToCard(new CommandAPDU(0, Constants.Instruction.TERMINAL_HELLO, 0, 0, termRndBytes));
        byte[] cardRndBytes = resp.getData();
        if(cardRndBytes.length != 4)
        	return false;

        // Send the public key of the terminal with the signature
        // 51 bytes (0..50) public key of the terminal
        // 54 bytes (51..104) signature of the key
        // Total: 105 bytes
        byte[] signedKey = new byte[105];
        System.arraycopy(ECCTerminal.PUBLIC_KEY_BYTES, 0, signedKey, 0, ECCTerminal.PUBLIC_KEY_BYTES.length);
        System.arraycopy(ECCTerminal.SIGNATURE_BYTES, 0, signedKey, ECCTerminal.PUBLIC_KEY_BYTES.length, ECCTerminal.SIGNATURE_BYTES.length);
        // P1 specifies what type of terminal this is:
        // P1 = 1 ==> charging terminal
        // P1 = 2 ==> pump terminal
        resp = this.cardComm.sendToCard(new CommandAPDU(0, Constants.Instruction.TERMINAL_KEY, this.type, 0, signedKey));
        byte[] data = resp.getData();
        if(data.length == 1) // means that only the error status was sent
        	return false;

        // Verify the public key and signature received from the card
        this.cardKeyBytes = new byte[51];
        byte[] cardSignatureBytes = new byte[54];
        System.arraycopy(data, 0, this.cardKeyBytes, 0, 51);
        System.arraycopy(data, 51, cardSignatureBytes, 0, 54);
        try {
			if(!ECCTerminal.verifyCardKey(this.cardKeyBytes, cardSignatureBytes))
				return false;
		} catch (GeneralSecurityException e) {
			System.out.println("An error occured while verifying the card key.");
			return false;
		}
		
		// Generate DH Secret
    	byte[] terminalSecret = ECCTerminal.performDH(this.cardKeyBytes);
    	// Uncomment this if using real card
    	//MessageDigest md = MessageDigest.getInstance("SHA");
    	//setKeys(termRndBytes, cardRndBytes, md.digest(terminalSecret));        
        
    	setKeys(termRndBytes, cardRndBytes, terminalSecret);
    	
    	//byte[] payload = SymTerminal.encrypt(new byte[]{0x01, 0x02, 0x03, 0x04});
    	resp = this.cardComm.sendToCard(new CommandAPDU(0, Constants.Instruction.CHANGE_CIPHER_SPEC, 1, 0));
    	data = resp.getData();
    	if(data.length != 1 || data[0] != 0x01)
    		return false;
    	
    	return true;
    }

    public void setKeys(byte[] termRndBytes, byte[] cardRndBytes, byte[] terminalSecret) throws CardException, GeneralSecurityException {
    	this.cardEncKey = new byte[16];
    	this.cardMacKey = new byte[16];
    	this.cardIV = new byte[16];
    	this.terminalEncKey = new byte[16];
    	this.terminalMacKey = new byte[16];
    	this.terminalIV = new byte[16];
    	
    	// Temp arrays
    	byte[] hashInput = new byte[34];	
    	byte[] hashOut = new byte[20];
    	
    	System.arraycopy(termRndBytes, 0, hashInput, 0, 4);
    	System.arraycopy(cardRndBytes, 0, hashInput, 4, 4);
    	//System.arraycopy(terminalSecret, 0, hashInput, 8, 20);
    	System.arraycopy(terminalSecret, 0, hashInput, 8, 25);

    	// cardEncKey
    	hashInput[33] = (byte) 0x00;
    	MessageDigest md = MessageDigest.getInstance("SHA");
    	md.update(hashInput);
    	hashOut = md.digest();    	
    	System.arraycopy(hashOut, 0, this.cardEncKey, 0, 16);
    	
    	// cardMacKey
    	hashInput[33] = (byte) 0x01;
    	md.reset();
    	md.update(hashInput);
    	hashOut = md.digest();    	
    	System.arraycopy(hashOut, 0, this.cardMacKey, 0, 16);
    	
    	// cardIV
    	hashInput[33] = (byte) 0x02;
    	md.reset();
    	md.update(hashInput);
    	hashOut = md.digest();    	
    	System.arraycopy(hashOut, 0, this.cardIV, 0, 16);
    	
    	// terminalEncKey
    	hashInput[33] = (byte) 0xA0;
    	md.reset();
    	md.update(hashInput);
    	hashOut = md.digest();    	
    	System.arraycopy(hashOut, 0, this.terminalEncKey, 0, 16);
    	
    	// terminalMACKey
    	hashInput[33] = (byte) 0xA1;
    	md.reset();
    	md.update(hashInput);
    	hashOut = md.digest();    	
    	System.arraycopy(hashOut, 0, this.terminalMacKey, 0, 16);
    	
    	// terminalIV
    	hashInput[33] = (byte) 0xA2;
    	md.reset();
    	md.update(hashInput);
    	hashOut = md.digest();    	
    	System.arraycopy(hashOut, 0, this.terminalIV, 0, 16);
    	
    	SymTerminal.init(terminalIV, cardIV, terminalEncKey, cardEncKey, terminalMacKey, cardMacKey);
    }
    
    public boolean checkPIN() {
    	byte pincode[] = this.askForPIN();
    	try {
			pincode = SymTerminal.encrypt(pincode);
		} catch (GeneralSecurityException e) {
			System.out.println("In AraTerminal.checkPIN a crypto exception occured");
			return false;
		}
		
        ResponseAPDU resp;
        try {
			resp = this.cardComm.sendToCard(new CommandAPDU(0, Constants.Instruction.CHECK_PIN, 0, 0, pincode));
		} catch (CardException e) {
			System.out.println("In AraTerminal.checkPIN an error occured while communicating with the card");
			return false;
		}
		
        byte[] respBytes = resp.getData();
        if(respBytes[0] == 0x01)
        		System.out.println("Correct PIN");
        else{
        		System.out.println("Wrong PIN");
        		System.out.println("Tries Remaining: " + String.valueOf(respBytes[1]));
        }
        
        return true;
    }


    private byte [] askForPIN(){
    	String input = null;
    	byte[] bytes = new byte[4];

        System.out.print("Enter PIN: ");
        Scanner in = new Scanner(System.in);
        try {
        	input = in.next();
        	Integer.parseInt(input);
        } catch(NumberFormatException e) {
        	System.out.println("Input is not a number");
        	System.exit(1);
        }
        
    	for(int i = 0; i < 4; i++)
        	 bytes[i] = (byte)String.valueOf(input).toCharArray()[i];
        return bytes;
    }
    
    /*
     * Get the current date in MySQL DATETIME format
     */
    
    protected String getDate(){
    	DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
    	return dateFormat.format(new Date());
    }
    
    protected short getBalance(){
        short balance = 0;
        try {
        	ResponseAPDU resp = this.cardComm.sendToCard(new CommandAPDU(0, Constants.Instruction.GET_BALANCE, 1, 0));
			byte[] data = resp.getData();
			balance = (short) ((data[1] << 8) + (data[0] & 0xff));
            if(debug) {
            	System.out.println("AraTerminal.getBalance returns the value");
            	for (byte b :  data)
            		System.out.format("0x%x ", b);
            	System.out.println("\nBalance is: " + balance);
            }
			if(balance < 0)
				System.out.println("In AraTerminal.getBalance an error occured because balance value is less than 0");
        } catch (CardException ex) {
        	System.out.println("In AraTerminal.getBalance an error occured when sending APDU to the card");
		}
    	return balance;
    }

    public static void main(String[] arg) throws CardException {
    	AraTerminal araTerminal = new AraTerminal((byte)0x01, (byte)0x01);
    	araTerminal.connectToCard();
    	araTerminal.disconnectFromCard();
    }
}
