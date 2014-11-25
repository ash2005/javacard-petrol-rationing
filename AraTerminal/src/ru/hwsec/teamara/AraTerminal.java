package ru.hwsec.teamara;

import java.util.Calendar;
import java.util.List;
import java.util.Random;

import javacard.framework.AID;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import com.licel.jcardsim.base.Simulator;

public class AraTerminal {

	static final byte[] ARA_APPLET_AID = new byte[]{ (byte) 0xde, (byte) 0xad, (byte) 0xba, (byte) 0xbe, (byte) 0x01 };
    static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, ARA_APPLET_AID);

    private byte[] PUBLIC_KEY_BYTES = new byte[]{
        (byte)0x04, (byte)0x50, (byte)0xd3, (byte)0x00, (byte)0xbd, (byte)0xab, (byte)0x65, (byte)0x46, (byte)0xc8, (byte)0x3d, (byte)0xbc, (byte)0xc3, (byte)0x28, (byte)0x6b, (byte)0xbb,
        (byte)0x1d, (byte)0x7a, (byte)0x89, (byte)0xf2, (byte)0xcd, (byte)0x38, (byte)0x84, (byte)0x06, (byte)0x59, (byte)0x75, (byte)0x13, (byte)0xd9, (byte)0xf5, (byte)0xb1, (byte)0xf7,
        (byte)0x21, (byte)0x3e, (byte)0xd6, (byte)0xe6, (byte)0xfe, (byte)0xad, (byte)0xdd, (byte)0xb5, (byte)0x50, (byte)0xa0, (byte)0x32, (byte)0x34, (byte)0x1c, (byte)0xda, (byte)0x4e,
        (byte)0xf3, (byte)0xf6, (byte)0x8f, (byte)0x59
    };

    private byte[] PRIVATE_KEY_BYTES = new byte[]{
        (byte)0x00, (byte)0xc6, (byte)0x57, (byte)0x81, (byte)0x21, (byte)0x85, (byte)0xec, (byte)0xa4, (byte)0xa1, (byte)0x6c, (byte)0x00, (byte)0x34, (byte)0x93, (byte)0xbf, (byte)0x05,
        (byte)0x49, (byte)0xb2, (byte)0xf5, (byte)0xd3, (byte)0x1f, (byte)0xd2, (byte)0x72, (byte)0x66, (byte)0x09, (byte)0x64
    };

    private byte[] SIGNATURE_BYTES = new byte[]{
    	(byte)0x30, (byte)0x35, (byte)0x02, (byte)0x18, (byte)0x36, (byte)0x01, (byte)0x6a, (byte)0x24, (byte)0x29, (byte)0x9e, (byte)0x78, (byte)0x3d, (byte)0x75, (byte)0x70, (byte)0x99,
    	(byte)0x32, (byte)0x54, (byte)0x51, (byte)0x15, (byte)0x2d, (byte)0x53, (byte)0x15, (byte)0x0d, (byte)0xb1, (byte)0x6c, (byte)0x5f, (byte)0xcb, (byte)0x25, (byte)0x02, (byte)0x19,
    	(byte)0x00, (byte)0xed, (byte)0xf2, (byte)0xfd, (byte)0xfc, (byte)0xc0, (byte)0x27, (byte)0x90, (byte)0xb8, (byte)0xa8, (byte)0x1f, (byte)0xa9, (byte)0x08, (byte)0xe8, (byte)0xa8,
    	(byte)0x76, (byte)0xbb, (byte)0x5a, (byte)0xd5, (byte)0x57, (byte)0xb2, (byte)0x68, (byte)0xee, (byte)0x57, (byte)0x87
    };

    private CardChannel applet;

    private AraTerminal() { }

    private void execute() {
    	TerminalFactory tf = TerminalFactory.getDefault();
    	CardTerminals ct = tf.terminals();
    	List<CardTerminal> cs;
		try {
			cs = ct.list(CardTerminals.State.CARD_PRESENT);
			if (cs.isEmpty()) {
	    		System.out.println("No terminals with a card found.");
	    		return;
	    	}
			while (true) {
	    		for(CardTerminal c : cs) {
	    			if (c.isCardPresent()) {
	    				Card card = c.connect("*");
	    	    		this.applet = card.getBasicChannel();
	    	    		if (this.applet.transmit(SELECT_APDU).getSW() != 0x9000)
	    	    			throw new CardException("Could no select AraApplet.");
                        this.performHandshake(this.applet);
	       	    	}
	    		}
	    	}


		} catch (CardException e) { }
    }
    
    private void executeSim() {
    	Simulator simulator = new Simulator();
    	AID aidInstance = new AID(ARA_APPLET_AID, (short)0, (byte)ARA_APPLET_AID.length);
    	AID someaid = simulator.installApplet(aidInstance, AraApplet.class);
    	if (simulator.selectApplet(someaid)) {
    		Random rnd = new Random(Calendar.getInstance().getTimeInMillis());
            byte[] termRndBytes = new byte[4];
            rnd.nextBytes(termRndBytes);
    		byte[] respBytes = simulator.transmitCommand(new CommandAPDU(0, Instruction.TERMINAL_HELLO, 0, 0, termRndBytes).getBytes());
    		byte[] cardRndBytes = new ResponseAPDU(respBytes).getData();
    		
    		byte[] signedKey = new byte[104];
            System.arraycopy(PUBLIC_KEY_BYTES, 0, signedKey, 0, PUBLIC_KEY_BYTES.length);
            System.arraycopy(SIGNATURE_BYTES, 0, signedKey, PUBLIC_KEY_BYTES.length, SIGNATURE_BYTES.length);
            respBytes = simulator.transmitCommand(new CommandAPDU(0, Instruction.TERMINAL_KEY, 1, 0, signedKey).getBytes());
            byte[] data = new ResponseAPDU(respBytes).getData();
            System.out.println(data.length);
    	} else
    		System.out.println("Could not select applet.");
    }

    private void performHandshake(CardChannel a) throws CardException {
        ResponseAPDU resp;
        // We first generate 4 random bytes to send the card
        Random rnd = new Random(Calendar.getInstance().getTimeInMillis());
        byte[] termRndBytes = new byte[4];
        rnd.nextBytes(termRndBytes);

        // Send TERMINAL_HELLO and get back the CARD_HELLO answer containing 4 random bytes
        resp = a.transmit(new CommandAPDU(0, Instruction.TERMINAL_HELLO, 0, 0, termRndBytes));
        byte[] cardRndBytes = resp.getData();
        System.out.println(cardRndBytes.length);
        
        // Send the public key of the terminal with the signature
        // 49 bytes (0..48) public key of the terminal; 49 bytes = 192 bits * 2 + 1 byte for the encoding type
        // 55 bytes (49..103) signature of the key
        // Total: 104 bytes
        byte[] signedKey = new byte[104];
        System.arraycopy(PUBLIC_KEY_BYTES, 0, signedKey, 0, PUBLIC_KEY_BYTES.length);
        System.arraycopy(SIGNATURE_BYTES, 0, signedKey, PUBLIC_KEY_BYTES.length, SIGNATURE_BYTES.length);
        // P1 specifies what type of terminal this is:
        // P1 = 1 ==> charging terminal
        // P1 = 2 ==> pump terminal
        resp = a.transmit(new CommandAPDU(0, Instruction.TERMINAL_KEY, 1, 0, signedKey));
        byte[] data = resp.getData();
        System.out.println(data.length);
        resp = null;
    }

    public static void main(String[] arg) {
    	(new AraTerminal()).execute();
    }
}
