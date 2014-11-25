package ru.hwsec.teamara;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Scanner;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

// Question: Should we do APDU communication inside the individual functions or inside execute() ?

public class Terminal {

    //Fields

    /* Trusted CA for verification of the CA's signature on card cert */
    private static byte[] cardIntermediateCA;

    /* cert 1 is used for mutual authentication and key exchange.
     * The signature is the hash of the concatenation of serialNumber + PublicKey + Expiry */

    private byte[] cert1SerialNumber;
    private byte[] cert1PubilcKey;
    private byte[] cert1PrivKey;
    private byte[] cert1Expiry;
    private byte[] cert1Signature;

	/* cert 2 is used for signatures for non-revocation. */
    private byte[] cert2SerialNumber;
    private byte[] cert2PubilcKey;
    private byte[] cert2PrivKey;
    private byte[] cert2Expiry;
    private byte[] cert2Signature;


    // APDU Communication
    static final byte[] ARA_APPLET_AID = new byte[]{ (byte) 0xde, (byte) 0xad, (byte) 0xba, (byte) 0xbe, (byte) 0x01 };
    static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, ARA_APPLET_AID);
    CardChannel applet;



    // Methods

    public Terminal(){ };

    /* verify that the certificate of card is correctly signed by card CA
     * and that the certificate is not expired */
    boolean verifyCert(byte[] cardSerialNumber, byte[] cardPublicKey, byte[] cardExpiry, byte[] cardSignature){
        return true;
    }

    /* Perform mutual authentication with the card.
     * Establish shared Diffie-Hellman Secret from Public Keys
     * Return secret key from DH Secret and nonces (used later in encrypt/decrypt)
     *  - Card write MAC key
     *  - Terminal write MAC key
     *  - Card write encryption key
     *  - Terminal write encryption key
     *  - Card write IV
     *  - Terminal write IV
     */
    byte[] mutualAuth(int nonceCard, int nonceTerminal, byte[] cardPublicKey){
        byte [] temp = {(byte) 0x00, (byte) 0x01};
        return temp;
    }

    /* Makes digital signature on transaction for non-repudiation */
    byte[] signTransaction(byte[] transaction){
        byte [] temp = {(byte) 0x00, (byte) 0x01};
        return temp;
    }

    /* Decrypt a received APDU payload.
    * Ciphertext Block comprises:
    *   - 16 byte IV
    *   - Ciphertext AES_CBC(msg + padding)
    *   - Integrity check (MAC(MAC_write_key, seq_num + plaintext))
    *   Ref: RFC 5246 6.2.3.2 (CBC) and 6.2.3.1 (HMAC)
    * Returns plaintext */
    byte[] decrypt(byte[] ciphertext, byte[] cardEncKey, byte[] cardMACKey){
        byte [] temp = {(byte) 0x00, (byte) 0x01};
        return temp;
    }


    /* Encrypt an APDU payload for sending.
     * Output ciphertext */
    byte[] encrypt(byte[] plaintext, byte[] terminalEncKey, byte[] terminalMACKey){
        byte [] temp = {(byte) 0x00, (byte) 0x01};
        return temp;
    }


    /* Ask user for a pin.
     * Send pin to card
     * return true if card returns success, else return false */
    /**
     * @return
     */
    /**
     * @return
     */
    
    // Asks for PIN and returns the byte array.
    private byte [] ask_for_PIN(){
    	String input = null;
    	byte[] bytes = ByteBuffer.allocate(4).putInt(1111).array(); // initialize
    	
        System.out.println("");
        System.out.print("Enter PIN: ");
        Scanner in = new Scanner( System.in );
        
        try{
        	input = in.next();
        	int pin = Integer.parseInt(input); // Just to check if it is an integer, var is not used.
        	
        	
        	int i = 0;
        	for(char charUserOutput : String.valueOf(input).toCharArray())
        	{
            	 bytes[i] = (byte) charUserOutput;
            	 i++;
        	}
            for (byte b : bytes)
            {
            	System.out.format("0x%x ", b);
            }
            System.out.println();
            
            
        } catch(NumberFormatException e) { 
        	System.out.println("Input is not a number");
        	System.exit(1);
        } catch (Exception e) {
            System.out.println("IO error.");
            System.exit(1);
        }	
        return bytes;
    }
    
    public void setPIN(CardChannel a) throws CardException {
    	byte pincode[] = ask_for_PIN();
    	
        ResponseAPDU resp;
        // Send TERMINAL_HELLO and get back the CARD_HELLO answer containing 4 random bytes
        resp = a.transmit(new CommandAPDU(0, Instruction.SET_PIN, 0, 0, pincode));
        byte[] cardRndBytes = resp.getData();
        System.out.println(cardRndBytes.length);
        for (byte b :  cardRndBytes)
        	System.out.format("0x%x ", b);
        System.out.println();
    }
    
    public boolean pinCheck(CardChannel a) throws CardException{
    	byte pincode[] = ask_for_PIN();
        ResponseAPDU resp;
        // Send TERMINAL_HELLO and get back the CARD_HELLO answer containing 4 random bytes
        resp = a.transmit(new CommandAPDU(0, Instruction.CHECK_PIN, 0, 0, pincode));
        byte[] cardRndBytes = resp.getData();
        System.out.println(cardRndBytes.length);
        for (byte b :  cardRndBytes)
        	System.out.format("0x%x ", b);
        System.out.println();        
        return true;
    }

    /* Check the revocation status of the card.
     * Return false if revoked.
     * Do not proceed further and end all communications with the card.*/
    boolean checkRevoke(){
        return true;
    }

    
    public byte[] intToBytes( final int i ) {
        ByteBuffer bb = ByteBuffer.allocate(4); 
        bb.putInt(i); 
        return bb.array();
    }

    /* Main state machine that calls the various methods defined above? */
    public void execute() throws CardException {
    	System.out.println("Entering execution...");
    	TerminalFactory tf = TerminalFactory.getDefault();
    	CardTerminals ct = tf.terminals();
    	List<CardTerminal> cs;
    	boolean loop = true;
		try {
			cs = ct.list(CardTerminals.State.CARD_PRESENT);
			if (cs.isEmpty()) {
	    		System.out.println("No terminals with a card found.");
	    		return;
	    	}
			while (loop) {
	    		for(CardTerminal c : cs) {
	    			if (c.isCardPresent()) {
	    				Card card = c.connect("*");
	    	    		this.applet = card.getBasicChannel();
	    	    		if (this.applet.transmit(SELECT_APDU).getSW() != 0x9000)
	    	    			throw new CardException("Could no select AraApplet.");
	    	    		this.setPIN(this.applet);
                        this.pinCheck(this.applet);
                        this.pinCheck(this.applet);
                        loop = false;
	       	    	}
	    		}
	    	}


		} catch (CardException e) { 
			System.out.println(e.getMessage());
		}
    }
}
