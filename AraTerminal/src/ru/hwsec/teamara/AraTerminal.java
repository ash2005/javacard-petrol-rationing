package ru.hwsec.teamara;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
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
        (byte)0x04, (byte)0x01, (byte)0x96, (byte)0x96, (byte)0x64, (byte)0x3a, (byte)0x14, (byte)0xda, (byte)0xe5, (byte)0x7c, (byte)0x15, (byte)0x83, (byte)0x6b, (byte)0x48, (byte)0x6f,
        (byte)0x83, (byte)0xac, (byte)0x4f, (byte)0x36, (byte)0x0a, (byte)0x47, (byte)0x9d, (byte)0x4b, (byte)0x9d, (byte)0x3e, (byte)0x85, (byte)0x01, (byte)0xd1, (byte)0x2d, (byte)0xf9,
        (byte)0x13, (byte)0x3a, (byte)0x70, (byte)0xee, (byte)0x9b, (byte)0xbb, (byte)0x58, (byte)0x65, (byte)0xc2, (byte)0x3d, (byte)0x29, (byte)0x9f, (byte)0xdb, (byte)0x54, (byte)0xac,
        (byte)0x2f, (byte)0x11, (byte)0x52, (byte)0x63, (byte)0xf2, (byte)0x9a
    };

    private byte[] PRIVATE_KEY_BYTES = new byte[]{
        (byte)0x00, (byte)0xf1, (byte)0xaf, (byte)0x06, (byte)0xac, (byte)0xa7, (byte)0x0d, (byte)0xf8, (byte)0x3f, (byte)0x89, (byte)0xd8, (byte)0x96, (byte)0x57, (byte)0x72, (byte)0x7d,
        (byte)0x93, (byte)0x79, (byte)0x1a, (byte)0xe8, (byte)0x76, (byte)0x7d, (byte)0xac, (byte)0x98, (byte)0x25, (byte)0x99
    };

    private byte[] SIGNATURE_BYTES = new byte[]{
        (byte)0x30, (byte)0x34, (byte)0x02, (byte)0x18, (byte)0x0c, (byte)0x4f, (byte)0xa8, (byte)0xdf, (byte)0x6f, (byte)0xd2, (byte)0x43, (byte)0x15, (byte)0xd3, (byte)0xf6, (byte)0xaa,
        (byte)0xb0, (byte)0xbd, (byte)0x34, (byte)0x6a, (byte)0x35, (byte)0x2a, (byte)0x9b, (byte)0xd7, (byte)0xb4, (byte)0x35, (byte)0x3e, (byte)0xbe, (byte)0x50, (byte)0x02, (byte)0x18,
        (byte)0x7f, (byte)0xa1, (byte)0x6a, (byte)0xd5, (byte)0x00, (byte)0x94, (byte)0xd2, (byte)0x90, (byte)0xa5, (byte)0xb4, (byte)0x6f, (byte)0xe3, (byte)0x85, (byte)0x7b, (byte)0xc8,
        (byte)0x48, (byte)0xcd, (byte)0xc8, (byte)0x03, (byte)0xc0, (byte)0x05, (byte)0x02, (byte)0xed, (byte)0x8f
    };

    private CardChannel applet;
    private boolean useSimulator;
    private Simulator simulator;

    private AraTerminal() {
    	this.useSimulator = false;
    }

    private void execute() {
    	TerminalFactory tf = TerminalFactory.getDefault();
    	CardTerminals ct = tf.terminals();
    	List<CardTerminal> cs;
		try {
			if(!this.useSimulator) {
				cs = ct.list(CardTerminals.State.CARD_PRESENT);
				if (cs.isEmpty()) {
		    		System.out.println("No terminals with a card found.");
		    		return;
		    	}
	    		for(CardTerminal c : cs) {
	    			if (c.isCardPresent()) {
	    				Card card = c.connect("*");
	    	    		this.applet = card.getBasicChannel();
	    	    		if (this.applet.transmit(SELECT_APDU).getSW() != 0x9000)
	    	    			throw new CardException("Could no select AraApplet.");
	    	    		break;
	    	    	}
	    		}
			}
			this.performHandshake();
		} catch (CardException e) { }
    }

    private void performHandshake() throws CardException {
        ResponseAPDU resp;
        // We first generate 4 random bytes to send the card
        Random rnd = new Random(Calendar.getInstance().getTimeInMillis());
        byte[] termRndBytes = new byte[4];
        rnd.nextBytes(termRndBytes);

        // Send TERMINAL_HELLO and get back the CARD_HELLO answer containing 4 random bytes
        resp = this.sendToCard(new CommandAPDU(0, Instruction.TERMINAL_HELLO, 0, 0, termRndBytes));
        byte[] cardRndBytes = resp.getData();
        System.out.println(cardRndBytes.length);

        // Send the public key of the terminal with the signature
        // 51 bytes (0..50) public key of the terminal
        // 54 bytes (51..104) signature of the key
        // Total: 105 bytes
        byte[] signedKey = new byte[105];
        System.arraycopy(PUBLIC_KEY_BYTES, 0, signedKey, 0, PUBLIC_KEY_BYTES.length);
        System.arraycopy(SIGNATURE_BYTES, 0, signedKey, PUBLIC_KEY_BYTES.length, SIGNATURE_BYTES.length);
        // P1 specifies what type of terminal this is:
        // P1 = 1 ==> charging terminal
        // P1 = 2 ==> pump terminal
        resp = this.sendToCard(new CommandAPDU(0, Instruction.TERMINAL_KEY, 1, 0, signedKey));
        byte[] data = resp.getData();

        // Verify the public key and signature received from the card
        byte[] cardKeyBytes = new byte[51];
        byte[] cardSignatureBytes = new byte[54];
        System.arraycopy(data, 0, cardKeyBytes, 0, 51);
        System.arraycopy(data, 51, cardSignatureBytes, 0, 54);
        try {
			System.out.println(ECCTerminal.verifyCardKey(cardKeyBytes, cardSignatureBytes));
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

    private ResponseAPDU sendToCard(CommandAPDU apdu) throws CardException {
        if(this.useSimulator) {
            byte[] respBytes = simulator.transmitCommand(apdu.getBytes());
    		return new ResponseAPDU(respBytes);
        } else
            return this.applet.transmit(apdu);
    }

    public static void main(String[] arg) {
    	AraTerminal araTerminal = new AraTerminal();
    	/*
    	//-----------------------------
    	// Comment the following lines to disable the simulator
    	araTerminal.useSimulator = true;
    	araTerminal.simulator = new Simulator();
    	AID appletAID = new AID(ARA_APPLET_AID, (short)0, (byte)ARA_APPLET_AID.length);
    	AID instanceAID = araTerminal.simulator.installApplet(appletAID, AraApplet.class);
    	araTerminal.simulator.selectApplet(instanceAID);
    	//-----------------------------
    	*/
    	araTerminal.execute();
    }
}
