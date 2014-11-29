package ru.hwsec.teamara;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Util;

public class Log {

	/* Transactions are byte arrays comprised of
	 * Terminal ID					: Byte 0...1
	 * Balance							: Byte 1...3			<  2 bytes >
	 * Date(e.g. 30)					: Byte 3...21			< 18 bytes >

	 * Terminal Signature			: Byte 21...75		< 54 bytes >
	 * Card Signature				: Byte 75...129		< 54 bytes >
	 */
	private static byte[] transaction1;
	private static byte[] transaction2;
	private static byte[] transaction3;
	private static byte[] transaction4;
	private static byte[] transaction5;
	private static short balance;
	private static short index;	// To indicate number of transactions currently stored
	
	public Log(){
	
		Log.transaction1 = new byte[129];
		Log.transaction2 = new byte[129];
		Log.transaction3 = new byte[129];
		Log.transaction4 = new byte[129];
		Log.transaction5 = new byte[129];
		
		Log.balance = 0;
		Log.index = 0;
	}
	
	//  PETROL PUMP FUNCTIONS
	
	public void getBalance(APDU apdu){
		switch(index){
		case (short) 1:
			getBalance(apdu, transaction1);
			break;
		case (short) 2:
			getBalance(apdu, transaction2);
			break;
		case (short) 3:
			getBalance(apdu, transaction3);
			break;
		case (short) 4:
			getBalance(apdu, transaction4);
			break;
		case (short) 5:
			getBalance(apdu, transaction5);
			break;
			default:
				break;
		}
	}
	private void getBalance(APDU apdu, byte[] transaction){
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 2);
        Util.arrayCopy(transaction, (short) 1, apdu.getBuffer(), (short)0, (short) 2);
        apdu.sendBytes((short)0, (short) 2); // (offset, length)
	}
	
	public boolean updateTransactionPetrol(APDU apdu){
		if (index<5){
			switch(index){
				case (short) 0:
					updateTransactionPetrol(apdu, transaction1);
					break;
				case (short) 1:
					updateTransactionPetrol(apdu, transaction2);
					break;
				case (short) 2:
					updateTransactionPetrol(apdu, transaction3);
					break;
				case (short) 3:
					updateTransactionPetrol(apdu, transaction4);
					break;
				case (short) 4:
					updateTransactionPetrol(apdu, transaction5);
					break;
				default:
					return false;
			}
			
			
			index ++;
			return true;
		}
		else
			return false;				
	}
	
	private void updateTransactionPetrol(APDU apdu, byte[] transaction){
		Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, transaction, (short)0, (short)75);
		ECCCard.performSignature(transaction, (short) 0, (short) 21, transaction, (short) 75);
		/* TODO: Add the balance updates
		 short newBalance;
		 
		newBalance = transaction[2] ;
		*/
	}
	
	
	
	
	//  CHARGING TERMINAL FUNCTIONS
	
	
	
	/* Send all logs to the Charging Terminal.
	 * Array formed by concatenate [transaction 1, transaction2, transactionN]
	 * Where n is the number of logs available.
	 *  Terminal can determine number of transactions = (Length of received APDU / 129 ) 
	 *  */
	public void getLogs(APDU apdu){
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 2);
        //TODO: make the array
        //Util.arrayCopy(transaction, (short) 1, apdu.getBuffer(), (short)0, (short) 2);
        apdu.sendBytes((short)0, (short) 2); // (offset, length)
	}
	
	public void updateTransactionCharge(APDU apdu){
        
		apdu.setOutgoing();
        apdu.setOutgoingLength((short) 2);
        
        Util.arrayCopy(resp, (short) 0, apdu.getBuffer(), (short)0, (short) 2);
        apdu.sendBytes((short)0, (short) 2); // (offset, length)
        
        Log.index = 0;
        
	}
}
