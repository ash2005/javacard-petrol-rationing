package ru.hwsec.teamara;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Log {

    private static byte[] transaction1;
    private static byte[] transaction2;
    private static byte[] transaction3;
    private static byte[] transaction4;
    private static byte[] transaction5;
    private static short index; // To indicate the number of transactions currently stored

    private static byte[] balance;
    private byte[] signature;
    private byte[] message;

    static{
        Log.transaction1 = new byte[Constants.Transaction.LOG_LENGTH];
        Log.transaction2 = new byte[Constants.Transaction.LOG_LENGTH];
        Log.transaction3 = new byte[Constants.Transaction.LOG_LENGTH];
        Log.transaction4 = new byte[Constants.Transaction.LOG_LENGTH];
        Log.transaction5 = new byte[Constants.Transaction.LOG_LENGTH];
        Log.index = 0;
        Log.balance = new byte[2]; // balance[0] corresponds to transaction[1], balance[1] corresponds to transaction[2],
    }

    public Log() {
        signature = JCSystem.makeTransientByteArray(Constants.Transaction.SIG_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        message = JCSystem.makeTransientByteArray(Constants.Transaction.MSG_TOSIGN_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    }

    /*
     * Pump terminal functions
     */
    
    public void getBalance(APDU apdu){
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 2);
        Util.arrayCopy(balance, (short)0, apdu.getBuffer(), (short)0, (short)2);
        apdu.sendBytes((short)0, (short)2);
    }

    public boolean updateTransactionPetrol(APDU apdu){
        if(index < 5) {
            switch(index) {
                case (short)0:
                    updateTransactionPetrol(apdu, Log.transaction1);
                    break;
                case (short)1:
                    updateTransactionPetrol(apdu, Log.transaction2);
                    break;
                case (short)2:
                    updateTransactionPetrol(apdu, Log.transaction3);
                    break;
                case (short)3:
                    updateTransactionPetrol(apdu, Log.transaction4);
                    break;
                case (short)4:
                    updateTransactionPetrol(apdu, Log.transaction5);
                    break;
                default:
            }
            index++;
            return true;
        } else
            return false;
    }

    private void updateTransactionPetrol(APDU apdu, byte[] transaction){
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, transaction, (short) 0, Constants.Transaction.MSG_TOSIGN_LENGTH);
        ECCCard.performSignature(transaction, (short) 0, (short)Constants.Transaction.MSG_TOSIGN_LENGTH, transaction, Constants.Transaction.CARD_SIG_OFFSET);
        //TODO: Throws SW:0x6F00!? why when updateTransactionCharge works?
        Log.balance[0] = transaction[Constants.Transaction.BALANCE_OFFSET];
        Log.balance[1] = transaction[Constants.Transaction.BALANCE_OFFSET + 1];
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)1);
        apdu.getBuffer()[0] = 0x01;
        apdu.sendBytes((short)0, (short)1);
    }

    /*
     * Charging terminal functions
     */
    
    public void getLastLog(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        if(index == 0) {
        	apdu.setOutgoingLength((short)1);
            buffer[0] = (byte)0xff;
            apdu.sendBytes((short)0, (short)1);
        } else {
        	apdu.setOutgoingLength(Constants.Transaction.LOG_LENGTH);
        	if(index == 1)
        		Util.arrayCopy(transaction1, (short)0, buffer, (short)0, Constants.Transaction.LOG_LENGTH);
        	else if(index == 2)
        		Util.arrayCopy(transaction2, (short)0, buffer, (short)0, Constants.Transaction.LOG_LENGTH);
        	else if(index == 3)
        		Util.arrayCopy(transaction3, (short)0, buffer, (short)0, Constants.Transaction.LOG_LENGTH);
        	else if(index == 4)
        		Util.arrayCopy(transaction4, (short)0, buffer, (short)0, Constants.Transaction.LOG_LENGTH);
        	else if(index == 5)
        		Util.arrayCopy(transaction5, (short)0, buffer, (short)0, Constants.Transaction.LOG_LENGTH);
        	apdu.sendBytes((short)0, Constants.Transaction.LOG_LENGTH);
        	index--;
        }
    }

    /* 
     * Clear the logs, reset the log index and return card ID
     */
    
    public void clearLogs(APDU apdu, byte cardID){
        Log.index = 0;
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)1);
        buffer[0] = cardID;
        apdu.sendBytes((short)0, (short)1);
    }

    /*
     * Updates the log with the new balance
     * Send card signature to charging terminal
     */
    
    public void updateTransactionCharge(APDU apdu){
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, message, (short) 0, Constants.Transaction.MSG_TOSIGN_LENGTH);
        ECCCard.performSignature(message, (short) 0, Constants.Transaction.MSG_TOSIGN_LENGTH , signature, (short)0);
        Log.balance[0] = message[Constants.Transaction.BALANCE_OFFSET];
        Log.balance[1] = message[Constants.Transaction.BALANCE_OFFSET + 1];

        Log.index = 0;
        apdu.setOutgoing();
        apdu.setOutgoingLength(Constants.Transaction.SIG_LENGTH);
        Util.arrayCopy(signature, (short) 0, apdu.getBuffer(), (short)0, Constants.Transaction.SIG_LENGTH);
        apdu.sendBytes((short)0, Constants.Transaction.SIG_LENGTH);
    }
}
