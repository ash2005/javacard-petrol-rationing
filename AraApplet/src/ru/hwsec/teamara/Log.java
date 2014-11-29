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
	private static byte[] balance;
	private static short index;	// To indicate number of transactions currently stored
	
	public Log(){
	
		Log.transaction1 = new byte[129];
		Log.transaction2 = new byte[129];
		Log.transaction3 = new byte[129];
		Log.transaction4 = new byte[129];
		Log.transaction5 = new byte[129];
		Log.balance = new byte[2];		// balance[0] corresponds to transaction[1], balance[1] corresponds to transaction[2],  
		
		Log.index = 0;
	}
		
	
	//  PETROL PUMP FUNCTIONS
	public void getBalance(APDU apdu){
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 2);
        Util.arrayCopy(balance, (short) 0, apdu.getBuffer(), (short)0, (short) 2);
        apdu.sendBytes((short)0, (short) 2); // (offset, length)
	}
	
	public boolean updateTransactionPetrol(APDU apdu){
		if (index<5){
			switch(index){
				case (short) 0:
					updateTransactionPetrol(apdu, Log.transaction1);
					break;
				case (short) 1:
					updateTransactionPetrol(apdu, Log.transaction2);
					break;
				case (short) 2:
					updateTransactionPetrol(apdu, Log.transaction3);
					break;
				case (short) 3:
					updateTransactionPetrol(apdu, Log.transaction4);
					break;
				case (short) 4:
					updateTransactionPetrol(apdu, Log.transaction5);
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
		Log.balance[0] =transaction[1];
		Log.balance[1] =transaction[2];
		//Log.balance = (short) (transaction[1] | (transaction[2]<< 8 ));		
		byte[] buffer = apdu.getBuffer();
		apdu.setOutgoing();
		buffer[0] = (byte) 0x01;					//	signifies OK
		apdu.sendBytes((short)0, (short) 1); // (offset, length)	
	}
	
	
	//  CHARGING TERMINAL FUNCTIONS	
	/** Send all logs to the Charging Terminal.
	 * Array formed by concatenate [transaction 1, transaction2, transactionN]
	 * Where n is the number of logs available.
	 *  Terminal can determine number of transactions = (Length of received APDU / 129 ) 
	 * */
	public void getLogs(APDU apdu){
		
		byte[] buffer = apdu.getBuffer();
		apdu.setOutgoing();
		
		switch(index){
			case (short) 0:
				apdu.setOutgoingLength((short) (1));
				buffer[0] = (byte) 0xff;						//	signifies no transaction
				apdu.sendBytes((short)0, (short) 1); // (offset, length)
				break;
			case (short) 1:
				apdu.setOutgoingLength((short) 129);
				Util.arrayCopy(transaction1, (short) 0, buffer, (short)0, (short) 129);
				apdu.sendBytes((short)0, (short) 129); // (offset, length)
				break;
			case (short) 2:
				apdu.setOutgoingLength((short) 258);			// 129 * 2
				Util.arrayCopy(transaction1, (short) 0, buffer, (short)0, (short) 129);
				Util.arrayCopy(transaction2, (short) 0, buffer, (short)129, (short) 129);
				apdu.sendBytes((short)0, (short) 258); // (offset, length)
				break;
			case (short) 3:
				apdu.setOutgoingLength((short) 387);			// 129 * 3
				Util.arrayCopy(transaction1, (short) 0, buffer, (short)0, (short) 129);
				Util.arrayCopy(transaction2, (short) 0, buffer, (short)129, (short) 129);
				Util.arrayCopy(transaction3, (short) 0, buffer, (short)258, (short) 129);
				apdu.sendBytes((short)0, (short) 387); 			// (offset, length)
				break;
			case (short) 4:
				apdu.setOutgoingLength((short) 516);			// 129 * 4
				Util.arrayCopy(transaction1, (short) 0, buffer, (short)0, (short) 129);
				Util.arrayCopy(transaction2, (short) 0, buffer, (short)129, (short) 129);
				Util.arrayCopy(transaction3, (short) 0, buffer, (short)258, (short) 129);
				Util.arrayCopy(transaction4, (short) 0, buffer, (short)387, (short) 129);
				apdu.sendBytes((short)0, (short) 516); 			// (offset, length)
				break;
			case (short) 5:
				apdu.setOutgoingLength((short) 645);			// 129 * 5
				Util.arrayCopy(transaction1, (short) 0, buffer, (short)0, (short) 129);
				Util.arrayCopy(transaction2, (short) 0, buffer, (short)129, (short) 129);
				Util.arrayCopy(transaction3, (short) 0, buffer, (short)258, (short) 129);
				Util.arrayCopy(transaction4, (short) 0, buffer, (short)387, (short) 129);
				Util.arrayCopy(transaction5, (short) 0, buffer, (short)516, (short) 129);
				apdu.sendBytes((short)0, (short) 645); 			// (offset, length)
				break;
			default:
				apdu.setOutgoingLength((short) (1));
				buffer[0] = (byte) 0xf0;						//	signifies error
				apdu.sendBytes((short)0, (short) 1); // (offset, length)
		}
	}

	/** Clear the logs. This function resets the log index and also returns card unique ID **/
	public void clearLogs(APDU apdu, byte cardID){
		Log.index = 0;
		byte[] buffer = apdu.getBuffer();
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) 1);
		buffer[0] = cardID;
		apdu.sendBytes((short)0, (short) 1);
	}	
	
	/** Updates the log with the new balance (old balance + 200).
	 * 	 Send Card Signature to Charging Terminal 
	 **/
	public void updateTransactionCharge(APDU apdu){
		updateTransactionPetrol(apdu, Log.transaction1);
        Log.index = 1;
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 54);
        Util.arrayCopy(transaction1, (short) 75, apdu.getBuffer(), (short)0, (short) 54);
        apdu.sendBytes((short)0, (short) 54); // (offset, length)
	}
}
