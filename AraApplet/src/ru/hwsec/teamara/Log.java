package ru.hwsec.teamara;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Log {

    /*
     * Log raw structure in the smart card:
     *             [ TermID | Date | Balance | Term Sig | Card Sig ]
     * Bytes:          1       19       2         56         56
     * Starting Pos:   0       1        20        22         78
     */
    private static byte[] transaction1;
    private static byte[] transaction2;
    private static byte[] transaction3;
    private static byte[] transaction4;
    private static byte[] transaction5;
    private static short index; // To indicate the number of transactions currently stored

    private static final short BALANCE_OFFSET           = 20;
    private static final short MSG_TOSIGN_LENGTH        = 22;
    private static final short CARD_SIGNATURE_OFFSET    = 78;
    private static final short PETROL_UPDATE_LENGTH     = 78;
    private static final short TRANSACTION_LENGTH       = 134;
    private static final short SIGNATURE_LENGTH         = 56;

    private static byte[] balance;
    private byte[] signature;
    private byte[] message;

    static{
        Log.transaction1 = new byte[TRANSACTION_LENGTH];
        Log.transaction2 = new byte[TRANSACTION_LENGTH];
        Log.transaction3 = new byte[TRANSACTION_LENGTH];
        Log.transaction4 = new byte[TRANSACTION_LENGTH];
        Log.transaction5 = new byte[TRANSACTION_LENGTH];
        Log.index = 0;
        Log.balance = new byte[2]; // balance[0] corresponds to transaction[1], balance[1] corresponds to transaction[2],
    }

    public Log() {
        signature = JCSystem.makeTransientByteArray(SIGNATURE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        message = JCSystem.makeTransientByteArray(MSG_TOSIGN_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    }

    //  PETROL PUMP FUNCTIONS
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
                    return false;
            }
            index++;
            return true;
        } else {
            // Default ring buffer mechanism
            byte[] aux = Log.transaction1;
            Log.transaction1 = Log.transaction2;
            Log.transaction2 = Log.transaction3;
            Log.transaction3 = Log.transaction4;
            Log.transaction4 = Log.transaction5;
            Log.transaction5 = aux;
            updateTransactionPetrol(apdu, Log.transaction5);
        }
    }

    private void updateTransactionPetrol(APDU apdu, byte[] transaction){
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, transaction, (short) 0, PETROL_UPDATE_LENGTH );
        ECCCard.performSignature(transaction, (short) 0, (short) MSG_TOSIGN_LENGTH, transaction, CARD_SIGNATURE_OFFSET );
        //TODO: Throws SW:0x6F00!? why when updateTransactionCharge works?
        Log.balance[0] = transaction[BALANCE_OFFSET];
        Log.balance[1] = transaction[BALANCE_OFFSET + 1];
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)1);
        apdu.getBuffer()[0] = 0x01;
        apdu.sendBytes((short)0, (short)1); // (offset, length)
    }


    //  CHARGING TERMINAL FUNCTIONS
    /** Send all logs to the Charging Terminal.
     * Array formed by concatenate [transaction 1, transaction2, transactionN]
     * Where n is the number of logs available.
     *  Terminal can determine number of transactions = (Length of received APDU / TRANSACTION_LENGTH )
     * */
    public void getLogs(APDU apdu){

        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();

        switch(index){
            case (short) 0:
                apdu.setOutgoingLength((short) (1));
                buffer[0] = (byte) 0xff;                        //  signifies no transaction
                apdu.sendBytes((short)0, (short) 1); // (offset, length)
                break;
            case (short) 1:
                apdu.setOutgoingLength((short) TRANSACTION_LENGTH);
                Util.arrayCopy(transaction1, (short) 0, buffer, (short)0, (short) TRANSACTION_LENGTH);
                apdu.sendBytes((short)0, (short) TRANSACTION_LENGTH); // (offset, length)
                index--;
                break;
            case (short) 2:
                apdu.setOutgoingLength((short) TRANSACTION_LENGTH);
                Util.arrayCopy(transaction2, (short) 0, buffer, (short)0, (short) TRANSACTION_LENGTH);
                apdu.sendBytes((short)0, (short) TRANSACTION_LENGTH); // (offset, length)
                index--;
                break;
            case (short) 3:
                apdu.setOutgoingLength((short) (TRANSACTION_LENGTH));
                Util.arrayCopy(transaction3, (short) 0, buffer, (short)0, (short) TRANSACTION_LENGTH);
                apdu.sendBytes((short)0, (short) TRANSACTION_LENGTH); // (offset, length)
                index--;
                break;
            case (short) 4:
                apdu.setOutgoingLength((short) (TRANSACTION_LENGTH));
                Util.arrayCopy(transaction4, (short) 0, buffer, (short)0, (short) TRANSACTION_LENGTH);
                apdu.sendBytes((short)0, (short) TRANSACTION_LENGTH); // (offset, length)
                index--;
                break;
            case (short) 5:
                apdu.setOutgoingLength((short) (TRANSACTION_LENGTH));
                Util.arrayCopy(transaction5, (short) 0, buffer, (short)0, (short) TRANSACTION_LENGTH);
                apdu.sendBytes((short)0, (short) TRANSACTION_LENGTH); // (offset, length)
                index--;
                break;
            default:
                apdu.setOutgoingLength((short) (1));
                buffer[0] = (byte) 0xf0;                        //  signifies error
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
     *   Send Card Signature to Charging Terminal
     **/
    public void updateTransactionCharge(APDU apdu){
        //updateTransactionPetrol(apdu, Log.transaction1);


        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, message, (short) 0, MSG_TOSIGN_LENGTH );
        ECCCard.performSignature(message, (short) 0, MSG_TOSIGN_LENGTH , signature, (short) 0);
        Log.balance[0] = message[BALANCE_OFFSET];
        Log.balance[1] = message[BALANCE_OFFSET + 1];

        Log.index = 0;
        apdu.setOutgoing();
        apdu.setOutgoingLength(SIGNATURE_LENGTH);
        Util.arrayCopy(signature, (short) 0, apdu.getBuffer(), (short)0, SIGNATURE_LENGTH);
        apdu.sendBytes((short)0, SIGNATURE_LENGTH); // (offset, length)
    }
}
