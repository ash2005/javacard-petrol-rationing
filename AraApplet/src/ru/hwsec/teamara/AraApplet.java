package ru.hwsec.teamara;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

import ru.hwsec.teamara.constants.CurrentState;
import ru.hwsec.teamara.constants.Instruction;

public class AraApplet extends Applet {

    private byte currentState;
    private byte[] transmem;

	public AraApplet() {
        this.register();
        this.currentState = CurrentState.ZERO;

        /*
         * Here we will store values which are session specific:
         * 4 bytes (0..3) int nonce sent by terminal in TERMINAL_HELLO message
         * 4 bytes (4..7) int nonce sent by card in CARD_HELLO message
         * 49 bytes (8..56) public key sent by the terminal
         * Total: 57 bytes
         */
        this.transmem = JCSystem.makeTransientByteArray((short)57, JCSystem.CLEAR_ON_DESELECT);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new AraApplet();
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

        // Get instruction received from the card and validate it
        byte ins = apdu.getBuffer()[ISO7816.OFFSET_INS];
		switch (ins) {
            case Instruction.TERMINAL_HELLO:
            this.processTerminalHello(apdu);
            break;

            default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
	}

    /*
     *  All the functions bellow are used for processing command APDUs sent by the terminal.
     */

    // This method processes the TERMINAL_HELLO command and sends back a CARD_HELLO
    private void processTerminalHello(APDU apdu) {
        if(this.currentState != CurrentState.ZERO)
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

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
     }
}
