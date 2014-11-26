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


public class PetrolTerminal extends Terminal {


    // Methods

    public PetrolTerminal(){
        super();
    }

    /* Check the revocation status of the card.
     * Return false if revoked.
     * Do not proceed further and end all communications with the card.*/
    //boolean checkRevoke(); 


    /* Reference sec 7.4 of Design Document
     * Get available balance from card (B)
     * Get requested fuel withdrawal amount from car owner (A)
     * Verify A < B else return false
     */
    boolean verifyBalance(){
    	return true;
    }

    /* Reference sec 7.4 of Design Document
     * Call this function if verifyBalance returns true
     * Create message and signature to update card balance.
     */
    boolean updateBalance(){
    	return true;
    }

}
