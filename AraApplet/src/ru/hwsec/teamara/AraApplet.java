package ru.hwsec.teamara;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.RandomData;
import javacard.security.KeyAgreement;

public class AraApplet extends Applet {

    private static byte[] PRIVATE_KEY_BYTES = {
        (byte)0x00, (byte)0xa2, (byte)0x7c, (byte)0x91, (byte)0xa2, (byte)0x97, (byte)0x8d, (byte)0x91, (byte)0xd6, (byte)0x06, (byte)0x5a, (byte)0x01, (byte)0x8c, (byte)0xde, (byte)0x2f,
        (byte)0x61, (byte)0x6f, (byte)0x54, (byte)0x1f, (byte)0xb5, (byte)0x33, (byte)0xe9, (byte)0xba, (byte)0xac, (byte)0xf1
    };

    private static byte[] PUBLIC_KEY_BYTES = {
        (byte)0x04, (byte)0x01, (byte)0x5b, (byte)0x41, (byte)0x1c, (byte)0x20, (byte)0x6d, (byte)0xff, (byte)0x82, (byte)0x17, (byte)0xc6, (byte)0x39, (byte)0x5e, (byte)0x49, (byte)0xe6,
        (byte)0x14, (byte)0x2e, (byte)0x86, (byte)0x11, (byte)0x01, (byte)0xb3, (byte)0x4f, (byte)0xe2, (byte)0x87, (byte)0x47, (byte)0xcd, (byte)0x00, (byte)0xa5, (byte)0x46, (byte)0x1f,
        (byte)0xae, (byte)0x4f, (byte)0x96, (byte)0xd8, (byte)0x43, (byte)0x11, (byte)0xef, (byte)0x7c, (byte)0x41, (byte)0x82, (byte)0x10, (byte)0x13, (byte)0x6f, (byte)0xc5, (byte)0x88,
        (byte)0x28, (byte)0x7d, (byte)0xb8, (byte)0x73, (byte)0x69, (byte)0x08
    };

    private static byte[] SIGNATURE_BYTES = {
        (byte)0x30, (byte)0x34, (byte)0x02, (byte)0x18, (byte)0x0f, (byte)0xa3, (byte)0xda, (byte)0xd3, (byte)0x65, (byte)0x44, (byte)0x30, (byte)0xf4, (byte)0x06, (byte)0x7a, (byte)0x7e,
        (byte)0xc7, (byte)0xac, (byte)0x79, (byte)0x9c, (byte)0x76, (byte)0x51, (byte)0x88, (byte)0x97, (byte)0x1c, (byte)0x5a, (byte)0xa7, (byte)0x4b, (byte)0x60, (byte)0x02, (byte)0x18,
        (byte)0x6d, (byte)0x15, (byte)0x24, (byte)0xb8, (byte)0xd9, (byte)0xde, (byte)0xe0, (byte)0xc1, (byte)0xb7, (byte)0xe5, (byte)0x88, (byte)0x11, (byte)0xe2, (byte)0xdc, (byte)0x12,
        (byte)0x32, (byte)0x4d, (byte)0xc0, (byte)0x6a, (byte)0xa2, (byte)0xbc, (byte)0xd1, (byte)0x48, (byte)0x5f
    };

    private byte currentState;
    private byte[] transmem;
    private byte permanentState;
    private byte[] buffer_PIN;
    private byte temp;

    // Maximum number of incorrect tries before the PIN is blocked.
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    // Maximum size PIN.
    final static byte MAX_PIN_SIZE = (byte) 0x04;
    OwnerPIN pin;

	public AraApplet() {
        this.currentState = CurrentState.ZERO;

        /*
         * Here we will store values which are session specific:
         * 4 bytes (0..3) int nonce sent by terminal in TERMINAL_HELLO message
         * 4 bytes (4..7) int nonce sent by card in CARD_HELLO message
         * 51 bytes (8..58) public key sent by the terminal
         * Total: 59 bytes
         */
        this.transmem = JCSystem.makeTransientByteArray((short)59, JCSystem.CLEAR_ON_DESELECT);

        this.pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        this.permanentState = PermanentState.INIT_STATE;
        //this.permanentState = PermanentState.ISSUED_STATE;
        
       
        this.buffer_PIN = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT); // initialize a 4bytes buffer for the PIN.

        this.register();
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		//new AraApplet(bArray, bOffset, bLength);
		new AraApplet();
	}


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

                    case Instruction.SET_KEY_EXPIRY:
                    	break;

                    case Instruction.SET_SIGNATURE:
                    	break;

                    case Instruction.SET_PIN:
                        this.setPIN(apdu);
                        break;

                    case Instruction.SET_BALANCE:
                    	break;

                    case Instruction.CHECK_PIN: // TODO: DELETE AFTER THIS LINE and MOVE under ISSUED_STATE state.
                    	this.checkPIN(apdu);
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

                    case Instruction.TERMINAL_KEY:
                        this.processTerminalKey(apdu);
                    break;

                    case Instruction.GEN_SHARED_SECRET:
                    	this.genSharedSecret(apdu);
                    break;

                    case Instruction.TERMINAL_CHANGE_CIPHER_SPEC:
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

    /*
     *  All the functions bellow are used for processing command APDUs sent by the terminal.
     */

	
    /* Initialise the PIN, as sent from the Terminal */
    void setPIN(APDU apdu){
        /*if(this.currentState != CurrentState.HELLO) { ????
            this.currentState = CurrentState.ZERO;
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }*/
    	//byte buffer_PIN[] = {0x03, 0x03, 0x03, 0x03}; // initialized in constructor.

        // Copy 4 bytes int nonce sent by terminal
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, this.buffer_PIN, (short)0, (short)4);

        this.pin.update(this.buffer_PIN, (short) 0, MAX_PIN_SIZE);
        
        /*// Sent the 4 bytes to the terminal // Just for testing....
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)4);
        Util.arrayCopy(this.buffer_PIN, (short)0, apdu.getBuffer(), (short)0, (short)4);
        apdu.sendBytes((short)0, (short)4); // (offset, length)
    	//*/
    }
    
    /* Check the user entered PIN */
    boolean checkPIN(APDU apdu){

    	this.temp = 0x00;
    	Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, this.buffer_PIN, (short)0, (short)4);
        if (this.pin.check(this.buffer_PIN, (short) 0, MAX_PIN_SIZE) == true){
        	this.temp = 0x01;
        }
        else{
        	this.temp = 0x00;
        }

        // Send 0x00 if PIN wrong, else 0x01
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)2);
        this.buffer_PIN[0] = this.temp;
        //this.buffer_PIN[1]= pin.getTriesRemaining();
        Util.arrayCopy(buffer_PIN, (short)0, apdu.getBuffer(), (short)0, (short)2);
        apdu.sendBytes((short)0, (short)2); // (offset, length)
        
    	return (temp == (byte) 0x01);
    }
	
	
	
    /* This method processes the TERMINAL_HELLO command and sends back a CARD_HELLO
	 * The 64-bit of random nonces are exchanged and stored in transmem[0...7]
	 */
    private void processTerminalHello(APDU apdu) {
        this.currentState = CurrentState.ZERO;

        // Copy 4 bytes int nonce sent by terminal
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, this.transmem, (short)0, (short)4);

        // Generate 4 bytes of random data and put them to transmem
        RandomData rnd = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rnd.generateData(this.transmem, (short)4, (short)4);

        // Sent the 4 bytes to the terminal
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)4);
        Util.arrayCopy(this.transmem, (short)4, apdu.getBuffer(), (short)0, (short)4);
        apdu.sendBytes((short)0, (short)4); // (offset, length)

        // Update the current state
        this.currentState = CurrentState.HELLO;
     }

    /* This method receives the Terminal certificate and verifies it
	 * If it is valid, the 51-byte terminal cert is stored in transmem[8...58]
	 */
     private void processTerminalKey(APDU apdu) {
        if(this.currentState != CurrentState.HELLO) {
            this.currentState = CurrentState.ZERO;
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        // Verify signature on the received public key
        boolean valid = false;
        if(apdu.getBuffer()[ISO7816.OFFSET_P1] == (byte)1)
            valid = ECCCard.verifyChargingTerminal(apdu.getBuffer(), ISO7816.OFFSET_CDATA);
        else if(apdu.getBuffer()[ISO7816.OFFSET_P1] == (byte)2)
            valid = ECCCard.verifyPumpTerminal(apdu.getBuffer(), ISO7816.OFFSET_CDATA);
        if(!valid) {
            // If verification fails then we abort
            this.currentState = CurrentState.ZERO;
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Verification went well if we got this far so we save the key
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, this.transmem, (short)8, (short)51);

        // Send our key with its own signature in return
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)(51 + 54));
        Util.arrayCopy(PUBLIC_KEY_BYTES, (short)0, apdu.getBuffer(), (short)0, (short)PUBLIC_KEY_BYTES.length);
        Util.arrayCopy(SIGNATURE_BYTES, (short)0, apdu.getBuffer(), (short)PUBLIC_KEY_BYTES.length, (short)SIGNATURE_BYTES.length);
        apdu.sendBytes((short)0, (short)(51 + 54));
        
        // Update the current state
        this.currentState = CurrentState.KEY_EXCHANGE;
     }

	 //Generate DH Secret
     private void genSharedSecret(APDU apdu) {
         if(this.currentState != CurrentState.KEY_EXCHANGE) {
             this.currentState = CurrentState.ZERO;
             ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
         }

         try{
         
         	KeyAgreement DH = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DHC, false);
         	DH.init(ECCCard.getPrivateKey(PRIVATE_KEY_BYTES));
         
        	 byte [] secret;
        	 secret = JCSystem.makeTransientByteArray((short)100, JCSystem.CLEAR_ON_DESELECT);
        	 short secretLength = DH.generateSecret(transmem, (short) 8, (short) 51, secret, (short) 0);	
        
        	 
        	 if (secretLength <1){
        		 byte[] buffer = apdu.getBuffer();
        		 apdu.setOutgoing();
    		     apdu.setOutgoingLength((short)1);
    		     buffer[0] = (byte) 0xff;
    		     apdu.sendBytes((short)0, (short)1); // (offset, length)
        	 }else{
    	         apdu.setOutgoing();
    	         apdu.setOutgoingLength(secretLength);
    	         Util.arrayCopy(secret, (short)0, apdu.getBuffer(), (short)0, secretLength);
    	         apdu.sendBytes((short)0, (short)secretLength); // (offset, length)
        	 }
        	 	
	         // Update the current state
	         this.currentState = CurrentState.CHANGE_CIPHER;
	         }
         
         catch (CryptoException e){
        	 byte[] buffer = apdu.getBuffer();
		     apdu.setOutgoing();
		     apdu.setOutgoingLength((short)1);
		     //buffer[0] = (byte) e.getReason();
		     buffer[0] = (byte) 0xfe;
		     apdu.sendBytes((short)0, (short)1); // (offset, length)
		     }
     }
     
     
}
