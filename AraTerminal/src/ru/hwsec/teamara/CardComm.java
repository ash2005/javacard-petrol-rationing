package ru.hwsec.teamara;

import java.util.List;

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

class CardComm {
	
	private static final boolean USE_SIMULATOR = true;
	
	static final byte[] ARA_APPLET_AID = new byte[]{ (byte) 0xde, (byte) 0xad, (byte) 0xba, (byte) 0xbe, (byte) 0x01 };
    static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, ARA_APPLET_AID);

    private Simulator simulator;
    private CardChannel applet;

    public CardComm() throws CardException {
        if(USE_SIMULATOR)
            this.initSimulator();
        else
            this.initCard();
    }

    public ResponseAPDU sendToCard(CommandAPDU apdu) throws CardException {
        if(USE_SIMULATOR) {
            byte[] respBytes = simulator.transmitCommand(apdu.getBytes());
    		return new ResponseAPDU(respBytes);
        } else
            return this.applet.transmit(apdu);
    }

    private void initSimulator() {
        this.simulator = new Simulator();
    	AID appletAID = new AID(ARA_APPLET_AID, (short)0, (byte)ARA_APPLET_AID.length);
    	AID instanceAID = this.simulator.installApplet(appletAID, AraApplet.class);
    	this.simulator.selectApplet(instanceAID);
    }

    private void initCard() throws CardException {
        TerminalFactory tf = TerminalFactory.getDefault();
    	CardTerminals ct = tf.terminals();
    	List<CardTerminal> cs = ct.list(CardTerminals.State.CARD_PRESENT);
        if(cs.isEmpty())
            throw new CardException("Could not find any cards.");
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
}
