package ru.hwsec.teamara;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;

public class AraApplet extends Applet {

    private static byte[] PRIVATE_KEY_BYTES = {
        (byte)0x00, (byte)0x96, (byte)0xeb, (byte)0x01, (byte)0x98, (byte)0x2d, (byte)0xa6, (byte)0xbd, (byte)0xc2, (byte)0x8f, (byte)0x01, (byte)0x5b, (byte)0x42, (byte)0xeb, (byte)0x97,
        (byte)0x5d, (byte)0xa6, (byte)0x7f, (byte)0xa2, (byte)0xcf, (byte)0x07, (byte)0x85, (byte)0x06, (byte)0x44, (byte)0x9a
    };

    private static byte[] PUBLIC_KEY_BYTES = {
        (byte)0x04, (byte)0x0b, (byte)0x14, (byte)0x5b, (byte)0x55, (byte)0x7a, (byte)0xd7, (byte)0xa3, (byte)0xca, (byte)0x56, (byte)0xd3, (byte)0x76, (byte)0x63, (byte)0xd1, (byte)0xa1,
        (byte)0x4f, (byte)0x8d, (byte)0x39, (byte)0x59, (byte)0xb3, (byte)0xf5, (byte)0x83, (byte)0x4b, (byte)0xe2, (byte)0x70, (byte)0xa9, (byte)0x87, (byte)0x7f, (byte)0x11, (byte)0x6b,
        (byte)0x57, (byte)0x9b, (byte)0x35, (byte)0x48, (byte)0x98, (byte)0xd4, (byte)0xef, (byte)0x0f, (byte)0x7a, (byte)0xbc, (byte)0x81, (byte)0x9c, (byte)0x18, (byte)0x3d, (byte)0xfa,
        (byte)0x40, (byte)0xfe, (byte)0x13, (byte)0xaa
    };

    private static byte[] SIGNATURE_BYTES = {
        (byte)0x30, (byte)0x35, (byte)0x02, (byte)0x18, (byte)0x5e, (byte)0x38, (byte)0x66, (byte)0x58, (byte)0x7c, (byte)0x9c, (byte)0xe8, (byte)0xdb, (byte)0x2a, (byte)0xf0, (byte)0xff,
        (byte)0xbc, (byte)0x11, (byte)0x29, (byte)0x3a, (byte)0x7c, (byte)0x61, (byte)0xc0, (byte)0xf1, (byte)0x03, (byte)0x36, (byte)0xfb, (byte)0xb7, (byte)0x2a, (byte)0x02, (byte)0x19,
        (byte)0x00, (byte)0xb0, (byte)0xdd, (byte)0xc1, (byte)0x6e, (byte)0x87, (byte)0x6e, (byte)0x15, (byte)0x2c, (byte)0x17, (byte)0x5b, (byte)0x47, (byte)0x9a, (byte)0x32, (byte)0x25,
        (byte)0x0f, (byte)0x19, (byte)0xb2, (byte)0x01, (byte)0xdc, (byte)0xc1, (byte)0x9c, (byte)0x68, (byte)0xe0, (byte)0x65
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
	
	public AraApplet(byte[] bArray, short bOffset, byte bLength) {

        //this.register();
        this.currentState = CurrentState.ZERO;

        /*
         * Here we will store values which are session specific:
         * 4 bytes (0..3) int nonce sent by terminal in TERMINAL_HELLO message
         * 4 bytes (4..7) int nonce sent by card in CARD_HELLO message
         * 51 bytes (8..58) public key sent by the terminal
         * Total: 59 bytes
         */
        this.transmem = JCSystem.makeTransientByteArray((short)59, JCSystem.CLEAR_ON_DESELECT);
        
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        permanentState = PermanentState.INIT_STATE;
        temp = 0x00;
        this.buffer_PIN = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT); // initialize a 4bytes buffer for the PIN. 
        this.register();

        register();
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new AraApplet(bArray, bOffset, bLength);
	}
    /* Initialise the PIN, as sent from the Terminal */
    boolean setPIN(APDU apdu){
        /*if(this.currentState != CurrentState.HELLO) { ????
            this.currentState = CurrentState.ZERO;
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }*/
    	//byte buffer_PIN[] = {0x03, 0x03, 0x03, 0x03}; // initialized in constructor.
        
        // Copy 4 bytes int nonce sent by terminal
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, buffer_PIN, (short)0, (short)4);
        
        this.pin.update(buffer_PIN, (short) 0, MAX_PIN_SIZE);
        
        // Sent the 4 bytes to the terminal // Just for testing....
        byte bytes[] = { 0x03, 0x03, 0x03, 0x03};
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)4);
        Util.arrayCopy(bytes, (short)0, apdu.getBuffer(), (short)0, (short)4);
        apdu.sendBytes((short)0, (short)4); // (offset, length)
    	return true;
    }
    
    boolean checkPIN(APDU apdu){
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, this.buffer_PIN, (short)0, (short)4);
        if (pin.check(buffer_PIN, (short) 0, MAX_PIN_SIZE) == true)
        	temp = 0x01;
        else
        	temp = 0x00;
        	
        byte bytes[] = { temp, 0x03, 0x03, 0x03};

        // Sent the 4 bytes to the terminal
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)4);
        Util.arrayCopy(bytes, (short)0, apdu.getBuffer(), (short)0, (short)4);
        apdu.sendBytes((short)0, (short)4); // (offset, length)
    	return pin.check(buffer_PIN, (short) 0, MAX_PIN_SIZE);
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

                    case Instruction.TERMINAL_TYPE:
                        //this.processTerminalType(apdu);
                    break;

                    case Instruction.TERMINAL_KEY:
                        this.processTerminalKey(apdu);
                    break;

                    case Instruction.TERMINAL_KEY_SIGNATURE:
                    break;

                    case Instruction.TERMINAL_GET_CARD_KEY:
                    break;

                    case Instruction.TERMINAL_GET_CARD_SIGNATURE:
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

    // This method processes the TERMINAL_HELLO command and sends back a CARD_HELLO
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

     private void processTerminalKey(APDU apdu) {
        if(this.currentState != CurrentState.HELLO) {
            this.currentState = CurrentState.ZERO;
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        // Verify signature on the received public key
        boolean valid = false;
        if(apdu.getBuffer()[ISO7816.OFFSET_P1] == (byte)1)
            valid = ECC.verifyChargingTerminal(apdu.getBuffer(), ISO7816.OFFSET_CDATA);
        else if(apdu.getBuffer()[ISO7816.OFFSET_P1] == (byte)2)
            valid = ECC.verifyPumpTerminal(apdu.getBuffer(), ISO7816.OFFSET_CDATA);
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
}
