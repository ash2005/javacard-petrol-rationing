package ru.hwsec.teamara;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyAgreement;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class AraApplet extends Applet {

    private OwnerPIN pin;
    private Log log;

    private byte currentState;
    private byte permanentState;
    private byte cardID;

    private byte[] transmem;
    private byte[] cardEncKey;
    private byte[] cardMacKey;
    private byte[] cardIV;
    private byte[] terminalEncKey;
    private byte[] terminalMacKey;
    private byte[] terminalIV;

	public AraApplet() {
        this.currentState = CurrentState.ZERO;
        this.pin = new OwnerPIN((byte)0x03, (byte)0x04);

        // The default PIN is '1111'
        byte[] buf = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
        buf[0] = 0x31;
        buf[1] = 0x31;
        buf[2] = 0x31;
        buf[3] = 0x31;
        this.pin.update(buf, (short) 0, MAX_PIN_SIZE);

        //this.permanentState = PermanentState.INIT_STATE;
        this.permanentState = PermanentState.ISSUED_STATE;

        this.log = new Log();
        this.cardID = (byte) 0xA1;

        /*
         * Here we will store values which are session specific:
         * 4 bytes (0..3) int nonce sent by terminal in TERMINAL_HELLO message
         * 4 bytes (4..7) int nonce sent by card in CARD_HELLO message
         * 656 bytes (7..663) scrap memory for encrypting/decrypting apdus
         * Total: 664
         */
        this.transmem = JCSystem.makeTransientByteArray((short)664, JCSystem.CLEAR_ON_DESELECT);

        /*
         * Initialize transient memory for crypto material
         */
	   	this.cardEncKey     = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
		this.cardMacKey     = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
		this.cardIV         = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
		this.terminalEncKey = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
		this.terminalMacKey = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
		this.terminalIV     = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);

        this.register();
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new AraApplet();
	}

	public boolean select() {
        // The applet declines to be selected if the pin is blocked.
        if(pin.getTriesRemaining() == 0)
            return false;
        return true;
    }

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if(selectingApplet()) {
			return;
		}

		byte[] buffer = apdu.getBuffer();
		byte ins = buffer[ISO7816.OFFSET_INS];

		switch(permanentState) {
            case PermanentState.INIT_STATE:
			switch (ins) {
                case Instruction.SET_PRIV_KEY:
                    this.setPrivateKey(apdu);
                    break;

                case Instruction.SET_PUB_KEY:
                    this.setPublicKey(apdu);
                    break;

                case Instruction.SET_PIN:
                    this.setPIN(apdu);
                    break;

                case Instruction.ISSUE_CARD:
                    this.issueCard(apdu);
                    break;

                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
			break;

            case PermanentState.ISSUED_STATE:
			switch (ins) {

                // HANDSHAKE stage
                case Instruction.TERMINAL_HELLO:
                    this.processTerminalHello(apdu);
                    break;

                case Instruction.TERMINAL_KEY:
                    this.processTerminalKey(apdu);
                    break;

                case Instruction.CHANGE_CIPHER_SPEC:
                    this.changeCipherSpec(apdu);
                    break;

                case Instruction.CHECK_PIN:
                    this.checkPIN(apdu);
                    break;


                // PUMPING stage
                case Instruction.GET_BALANCE:
                    this.log.getBalance(apdu);
                    break;

                case Instruction.UPDATE_BALANCE_PETROL:
                    this.log.updateTransactionPetrol(apdu);
                    break;

                // CHARGING stage.
                case Instruction.GET_LOGS:
                    this.log.getLogs(apdu);
                    break;

                case Instruction.CLEAR_LOGS:
                    this.log.clearLogs(apdu, this.cardID);
                    break;

                case Instruction.UPDATE_BALANCE_CHARGE:
                    this.log.updateTransactionCharge(apdu);
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

    private void setPrivateKey(APDU apdu) {
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, ECCCard.PRIVATE_KEY_BYTES, (short)0, (short)25);
        this.sendSuccess(apdu);
    }

	private void setPublicKey(APDU apdu) {
		Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, ECCCard.PRIVATE_KEY_BYTES, (short)0, (short)50);
		this.sendSuccess(apdu);
	}

    private void setPIN(APDU apdu) {
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, this.transmem, (short)59, (short)4);
        this.pin.update(this.transmem, (short)59, MAX_PIN_SIZE);
        this.sendSuccess(apdu);
    }

    private void issueCard(APDU apdu) {
    	this.permanentState = PermanentState.ISSUED_STATE;
    	this.sendSuccess(apdu);
    }

    boolean checkPIN(APDU apdu){
    	SymApplet.decrypt(apdu.getBuffer(), ISO7816.OFFSET_CDATA, (byte)16, this.transmem, (short)59);
        if(this.pin.check(this.transmem, (short) 59, MAX_PIN_SIZE) == true) {
        	this.sendPINSuccess(apdu, this.pin.getTriesRemaining());
            return true;
        } else {
            this.sendPINFailure(apdu, this.pin.getTriesRemaining());
            return false;
        }
    }

    /*
     * This method processes the TERMINAL_HELLO command and sends back a CARD_HELLO
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
        apdu.sendBytes((short)0, (short)4);

        // Update the current state
        this.currentState = CurrentState.HELLO;
     }

    /*
     * This method receives the Terminal certificate and verifies it
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
            this.sendFailure(apdu);
            return;
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

    /*
     * This method generates the DH shared secret from the private key (a scalar)
     * and the public key of the terminal sent in the previous APDU
     */

    private void changeCipherSpec(APDU apdu) {
        if(this.currentState != CurrentState.KEY_EXCHANGE) {
            this.currentState = CurrentState.ZERO;
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        try {
            KeyAgreement DH = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
            DH.init(ECCCard.getCardPrivateKey());
            short secretLength = DH.generateSecret(transmem, (short) 8, (short) 51, transmem, (short) 8);
            if(secretLength < 1)
                this.sendFailure(apdu);
            else {
                this.genSecretKeys();
                this.sendSuccess(apdu);
            }
            // Update the current state
            this.currentState = CurrentState.CHANGE_CIPHER;
        } catch (CryptoException e) {
            this.sendFailure(apdu);
        }
    }

    private void genSecretKeys() {
        MessageDigest hash = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        transmem[28] = (byte) 0x00;
        transmem[29] = (byte) 0x00;
        transmem[30] = (byte) 0x00;
        transmem[31] = (byte) 0x00;
        transmem[32] = (byte) 0x00;

        transmem[33] = (byte) 0x00;	//cardEncKey
        hash.doFinal(this.transmem, (short)0, (short)34, this.transmem, (short)35);
        Util.arrayCopy(this.transmem, (short)35, this.cardEncKey, (short)0, (short)16);

        transmem[33] = (byte) 0x01;	//cardMacKey
        hash.reset();
        hash.doFinal(this.transmem, (short)0, (short)34, this.transmem, (short)35);
        Util.arrayCopy(this.transmem, (short)35, this.cardMacKey, (short)0, (short)16);

        transmem[33] = (byte) 0x02;	//cardIV
        hash.reset();
        hash.doFinal(this.transmem, (short)0, (short)34, this.transmem, (short)35);
        Util.arrayCopy(this.transmem, (short)35, this.cardIV, (short)0, (short)16);

        transmem[33] = (byte) 0xA0;	//TerminalEncKey
        hash.reset();
        hash.doFinal(this.transmem, (short)0, (short)34, this.transmem, (short)35);
        Util.arrayCopy(this.transmem, (short)35, this.terminalEncKey, (short)0, (short)16);

        transmem[33] = (byte) 0xA1;	//TerminalMacKey
        hash.reset();
        hash.doFinal(this.transmem, (short)0, (short)34, this.transmem, (short)35);
        Util.arrayCopy(this.transmem, (short)35, this.terminalMacKey, (short)0, (short)16);

        transmem[33] = (byte) 0xA2;	//Terminal IV
        hash.reset();
        hash.doFinal(this.transmem, (short)0, (short)34, this.transmem, (short)35);
        Util.arrayCopy(this.transmem, (short)35, this.terminalIV, (short)0, (short)16);

        SymApplet.init(cardIV, (short)0, terminalIV, (short)0, cardEncKey, (short)0, terminalEncKey, (short)0, cardMacKey, (short)0, terminalMacKey, (short)0);
    }

    /*
     * Functions for reporting success or failure back to the terminal.
     */

    private void sendSuccess(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)1);
        apdu.getBuffer()[0] = (byte)0x01;
        apdu.sendBytes((short)0, (short)1);
    }

    private void sendFailure(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)1);
        apdu.getBuffer()[0] = (byte)0x00;
        apdu.sendBytes((short)0, (short)1);
    }

    private void sendPINSuccess(APDU apdu, byte remainingTries) {
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)2);
        apdu.getBuffer()[0] = (byte)0x01;
        apdu.getBuffer()[1] = remainingTries;
        apdu.sendBytes((short)0, (short)2);
    }

    private void sendPINFailure(APDU apdu, byte remainingTries) {
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)2);
        apdu.getBuffer()[0] = (byte)0x00;
        apdu.getBuffer()[1] = remainingTries;
        apdu.sendBytes((short)0, (short)2);
    }
}
