package ru.hwsec.teamara;

import java.security.GeneralSecurityException;
import java.util.Scanner;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class PetrolTerminal extends AraTerminal {

    public PetrolTerminal(byte termID){
        super(termID, (byte)0x02);
    }

    /* 
     * Get requested fuel withdrawal amount from car owner 
     * and verify that there is enough balance.
     */
    
    private int askForAmount(int balance){
        int amount = 0;
        Scanner in = new Scanner(System.in);
        System.out.print("Enter amount: ");
        while(true){	        
	        try {
	        	amount = Integer.parseInt(in.next());
	        	if(amount > balance)
	        		System.out.println("There is not enough balance on the card.");
	        	else
	        		break;
	        } catch(NumberFormatException ex) {
	        	System.out.print("Invalid integer, try again: ");
	        }
        }
        return amount;
    }
    
    /* 
     * Reference section 7.4 of Design Document
     * Call this function if verifyBalance returns true
     * Create message and signature to update card balance.
     */
    
    private boolean updateBalance(short newBalance){
    	byte[] messageBytes = new byte[Constants.Transaction.MSG_TOSIGN_LENGTH];
    	byte[] signatureBytes = null;
    	byte[] transactionBytes = new byte[Constants.Transaction.PETROL_TRANSACTION_LENGTH];
    	byte[] currentDate = this.getDate().getBytes();
		int dateLength = currentDate.length;
		
		if(debug && dateLength != Constants.Transaction.DATE_LENGTH)
			System.out.println("In PetrolTerminal.updateBalance the length of the current date is wrong");
		
		messageBytes[0] = this.termID;
		System.arraycopy(currentDate, 0, messageBytes, Constants.Transaction.DATE_OFFSET, Constants.Transaction.DATE_LENGTH);
		messageBytes[Constants.Transaction.BALANCE_OFFSET] = (byte)(newBalance);
		messageBytes[Constants.Transaction.BALANCE_OFFSET + 1] = (byte)((newBalance >> 8) & 0xFF);
		
		try {
			signatureBytes = ECCTerminal.performSignature(messageBytes);
		} catch (GeneralSecurityException e) {
			System.out.println("In PetrolTerminal.updateBalance a crypto exception occured");
		}
		
		System.arraycopy(messageBytes, 0, transactionBytes, 0, Constants.Transaction.MSG_TOSIGN_LENGTH);
		System.arraycopy(signatureBytes, 0, transactionBytes, Constants.Transaction.TERM_SIG_OFFSET, signatureBytes.length);
		try {
			ResponseAPDU resp = this.cardComm.sendToCard(new CommandAPDU(0, Constants.Instruction.UPDATE_BALANCE_PETROL, 0, 0, transactionBytes));
			if (resp.getData()[0] == (byte) 0x01)
				System.out.println("Petrol Deduction is successful. You can withdraw fuel now.");
			else
				System.out.println("Petrol Deduction unsuccessful. Please try again.");
		} catch (CardException ex) {
			System.out.println("In PetrolTerminal.updateBalance an error occured when sending an APDU to the card");
		}		
    	return true;
    }
    
    public void use() {
    	System.out.println("Welcome to petrol pump terminal.");
    	short balance = this.getBalance();
    	
    	System.out.println("Your current balance is " + String.valueOf(balance));
    	if(balance <= 1) {
    		System.out.println("The card does not have enough balance. Card is disconnected.");
    		System.out.println();
    		return;
    	}
    	
    	int amount = askForAmount(balance);
    	int newBalance = balance - amount; 
    	boolean status = updateBalance((short)newBalance);
    	if(!status)
    		System.out.println("Error, pumping failed.");
    	else
    		System.out.println("Pumping has been completed.");
    }

}
