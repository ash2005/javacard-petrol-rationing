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

    private byte currentState;
    private byte[] transmem;
    private byte permanentState;
    private byte temp;

    // Maximum number of incorrect tries before the PIN is blocked.
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    // Maximum size PIN.
    final static byte MAX_PIN_SIZE = (byte) 0x04;
    OwnerPIN pin;

	public AraApplet() {
        this.currentState = CurrentState.ZERO;
        this.pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        //this.permanentState = PermanentState.INIT_STATE;
        this.permanentState = PermanentState.ISSUED_STATE;

        /*
         * Here we will store values which are session specific:
         * 4 bytes (0..3) int nonce sent by terminal in TERMINAL_HELLO message
         * 4 bytes (4..7) int nonce sent by card in CARD_HELLO message
         * 51 bytes (8..58) public key sent by the terminal
         * 4 bytes (59..62) for the PIN
         * Total: 63 bytes
         */
        this.transmem = JCSystem.makeTransientByteArray((short)63, JCSystem.CLEAR_ON_DESELECT);

        this.register();
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
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
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, this.transmem, (short)59, (short)4);
        this.pin.update(this.transmem, (short)59, MAX_PIN_SIZE);

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
    	Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, this.transmem, (short)59, (short)4);
        if (this.pin.check(this.transmem, (short) 59, MAX_PIN_SIZE) == true)
        	this.temp = 0x01;
        else
        	this.temp = 0x00;

        // Send 0x00 if PIN wrong, else 0x01
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)2);
        this.transmem[59] = this.temp;
        //this.buffer_PIN[1]= pin.getTriesRemaining();
        Util.arrayCopy(transmem, (short)59, apdu.getBuffer(), (short)0, (short)2);
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
        Util.arrayCopy(ECCCard.PUBLIC_KEY_BYTES, (short)0, apdu.getBuffer(), (short)0, (short)ECCCard.PUBLIC_KEY_BYTES.length);
        Util.arrayCopy(ECCCard.SIGNATURE_BYTES, (short)0, apdu.getBuffer(), (short)ECCCard.PUBLIC_KEY_BYTES.length, (short)ECCCard.SIGNATURE_BYTES.length);
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

        try {
            KeyAgreement DH = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DHC, false);
            DH.init(ECCCard.getCardPrivateKey());

            byte [] secret;
            secret = JCSystem.makeTransientByteArray((short)100, JCSystem.CLEAR_ON_DESELECT);
            short secretLength = DH.generateSecret(transmem, (short) 8, (short) 51, secret, (short) 0);

            if(secretLength < 1) {
                byte[] buffer = apdu.getBuffer();
                apdu.setOutgoing();
                apdu.setOutgoingLength((short)1);
                buffer[0] = (byte) 0xff;
                apdu.sendBytes((short)0, (short)1);
            } else {
                apdu.setOutgoing();
                apdu.setOutgoingLength(secretLength);
                Util.arrayCopy(secret, (short)0, apdu.getBuffer(), (short)0, secretLength);
                apdu.sendBytes((short)0, (short)secretLength); // (offset, length)
            }

            // Update the current state
            this.currentState = CurrentState.CHANGE_CIPHER;
        } catch (CryptoException e) {
            byte[] buffer = apdu.getBuffer();
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)1);
            //buffer[0] = (byte) e.getReason();
            buffer[0] = (byte) 0xfe;
            apdu.sendBytes((short)0, (short)1); // (offset, length)
        }
    }
}
