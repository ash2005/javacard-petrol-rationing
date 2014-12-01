package ru.hwsec.teamara;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class PersonalisationTerminal {
	
	protected CardComm cardComm;
	
	public PersonalisationTerminal() {
        try {
			this.cardComm = new CardComm();
		} catch (CardException e) {
			System.out.println("Could not connect to the card or simulator.");
		}
    }
	
	public boolean issueCard() throws CardException {
		byte[] cardPrivateKey = {};
		byte[] cardPublicKey = {};
		byte[] cardPin = {};
		
		ResponseAPDU resp = this.cardComm.sendToCard(new CommandAPDU(0, Constants.Instruction.SET_PRIV_KEY, 1, 0, cardPrivateKey));
        byte[] data = resp.getData();
        if(data.length != 1 || data[0] != 1)
        	return false;
		
        resp = this.cardComm.sendToCard(new CommandAPDU(0, Constants.Instruction.SET_PUB_KEY, 1, 0, cardPublicKey));
        data = resp.getData();
        if(data.length != 1 || data[0] != 1)
        	return false;
        
        resp = this.cardComm.sendToCard(new CommandAPDU(0, Constants.Instruction.SET_PIN, 1, 0, cardPin));
        data = resp.getData();
        if(data.length != 1 || data[0] != 1)
        	return false;
        
        resp = this.cardComm.sendToCard(new CommandAPDU(0, Constants.Instruction.ISSUE_CARD, 1, 0));
        data = resp.getData();
        if(data.length != 1 || data[0] != 1)
        	return false;
        
		return true;
	}
}
