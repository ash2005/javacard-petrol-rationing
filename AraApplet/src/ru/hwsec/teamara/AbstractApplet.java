package ru.hwsec.teamara;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Applet;
import javacard.framework.ISOException;

public abstract class AbstractApplet extends Applet {

    private byte currentState;
    private byte permanentState;

	public AbstractApplet() {
        this.register();
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		//new AbstractApplet(); //Commented to avoid compiler complaints
	}
    abstract void processTerminalHello(APDU apdu);
    abstract void processTerminalKey(APDU apdu);
    abstract void processTerminalType(APDU apdu);

    /* Perform mutual authentication with the Terminal.
     * Establish shared Diffie-Hellman Secret from Public Keys
     * Return secret key from DH Secret and nonces (used later in encrypt/decrypt)
     *  - Card write MAC key
     *  - Terminal write MAC key
     *  - Card write encryption key
     *  - Terminal write encryption key
     *  - Card write IV
     *  - Terminal write IV
     */
    abstract byte[] mutualAuth(short nonceCard, short nonceTerminal, byte[] cardPublicKey);


    /* Decrypt a received APDU payload.
    * Ciphertext Block comprises:
    *   - 16 byte IV
    *   - Ciphertext AES_CBC(msg + padding)
    *   - Integrity check (MAC(MAC_write_key, seq_num + plaintext))
    *   Ref: RFC 5246 6.2.3.2 (CBC) and 6.2.3.1 (HMAC)
    * Returns plaintext */
    abstract byte[] decrypt(byte[] ciphertext, byte[] cardEncKey, byte[] cardMACKey);


    /* Encrypt an APDU payload for sending.
     * Output ciphertext */
    abstract byte[] encrypt(byte[] plaintext, byte[] terminalEncKey, byte[] terminalMACKey);


    /* Verify pin and update tries */
    abstract boolean pinCheck();


    /* Makes digital signature on transaction for non-repudiation */
    abstract byte[] signTransaction(byte[] transaction);

    /* Update Logbook function
     * Note: remember to update the log index
     * */
    abstract boolean updateLog(short balance, byte[] signatureCard, byte[] signatureTerminal);


    /* Send Logbook data to Charging Terminal
     * Note: remember to delete the logs after done
     * */
    abstract boolean sendLog(short balance, byte[] signatureCard, byte[] signatureTerminal);



    /* Revoke the card by updating some status flag. */
    abstract boolean revoke();

    /* Initialise the PIN, as sent from the Terminal */
    abstract boolean setPIN(APDU apdu);


	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        switch(permanentState){
            case PermanentState.INIT_STATE:
                switch (ins) {
        	    	case Instruction.SET_PRIV_KEY:
        			break;

                    case Instruction.SET_PIN:
                        this.setPIN(apdu);
                    break;

    	    	default:
    		    	// good practice: If you don't know the INStruction, say so:
    			    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		        }

                break;

            case PermanentState.ISSUED_STATE:
                switch (ins) {
        	    	case Instruction.TERMINAL_HELLO:
                        this.processTerminalHello(apdu);
        			break;

                    case Instruction.TERMINAL_TYPE:
                        this.processTerminalType(apdu);
                    break;

                    case Instruction.TERMINAL_KEY:
                        this.processTerminalKey(apdu);
                    break;

    	    	default:
    		    	// good practice: If you don't know the INStruction, say so:
    			    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		        }

                break;



        default:
		   	// good practice: If you don't know the INStruction, say so:
		    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
	}

}
