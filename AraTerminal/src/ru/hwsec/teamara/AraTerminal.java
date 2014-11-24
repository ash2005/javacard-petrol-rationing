package ru.hwsec.teamara;

import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import ru.hwsec.teamara.constants.Instruction;

public class AraTerminal {

	static final byte[] ARA_APPLET_AID = { (byte) 0xde, (byte) 0xad, (byte) 0xba, (byte) 0xbe, (byte) 0x01 };
    static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, ARA_APPLET_AID);

    CardChannel applet;

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
	    	    		ResponseAPDU resp = this.applet.transmit(SELECT_APDU);
	    	    		if (resp.getSW() != 0x9000) {
	    	    			throw new CardException("Could no select AraApplet.");
	    	    		}
	    	    		resp = this.applet.transmit(new CommandAPDU(0, Instruction.TERMINAL_HELLO, 0, 0));
	    	    		byte[] data = resp.getData();
	    	    		int x;
	    	    		x = 2;
	    	    	}
	    		}
	    	}


		} catch (CardException e) { }
    }

    public static void main(String[] arg) {
    	(new AraTerminal()).execute();
    }
}
