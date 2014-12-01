package ru.hwsec.teamara;

public class Constants {
	
	public static class CurrentState {
	    private CurrentState() { }
	    
	    public static final byte ZERO           = (byte)0;
	    public static final byte HELLO          = (byte)1;
	    public static final byte KEY_EXCHANGE	= (byte)2;
	    public static final byte CHANGE_CIPHER	= (byte)3;
	}
	
	public static class PermanentState {
	    private PermanentState() { }
	    
	    public static final byte INIT_STATE     = (byte) 0x00;
	    public static final byte ISSUED_STATE   = (byte) 0x01;
	}

	public static class Transaction {
		private Transaction() { }
		
	    /*
	     * Log raw structure in the smart card:
	     *             [ TermID | Date | Balance | Term sig | Card sig ]
	     * Bytes:          1       19       2         56         56
	     * Offset:         0       1        20        22         78
	     */
		
		public static final short DATE_OFFSET  				= 1;
		public static final short BALANCE_OFFSET			= 20;
		public static final short TERM_SIG_OFFSET			= 22;
		public static final short CARD_SIG_OFFSET			= 78;
		
		public static final short TERM_ID_LENGTH			= 1;
		public static final short DATE_LENGTH 				= 19;
		public static final short BALANCE_LENGTH			= 2;
		public static final short MSG_TOSIGN_LENGTH     	= TERM_ID_LENGTH + DATE_LENGTH + BALANCE_LENGTH;
		public static final short SIG_LENGTH  				= 56;
		public static final short PETROL_TRANSACTION_LENGTH = MSG_TOSIGN_LENGTH + SIG_LENGTH;
		public static final short LOG_LENGTH    			= MSG_TOSIGN_LENGTH + 2 * SIG_LENGTH;
	}
	
	public class Instruction {
		private Instruction() { }

	    // Personaltization Terminal
	    public static final byte SET_PRIV_KEY   = (byte)0x00;
	    public static final byte SET_PUB_KEY	= (byte)0x01;
	    public static final byte SET_PIN        = (byte)0x02;
	    public static final byte ISSUE_CARD		= (byte)0x03;

	    // Mutual Authentication
	    public static final byte TERMINAL_HELLO = (byte)0x10;
	    public static final byte TERMINAL_TYPE  = (byte)0x11;
	    public static final byte TERMINAL_KEY   = (byte)0x12;
	    public static final byte CHANGE_CIPHER_SPEC    = (byte)0x14;

	    // Checks
	    public static final byte CHECK_PIN      = (byte)0x20; // move under issued state.
	    
	    // Petrol Terminal
	    public static final byte GET_BALANCE  = (byte)0x30;
	    public static final byte UPDATE_BALANCE_PETROL = (byte)0x31;
	    
	    // Charging Terminal
	    public static final byte GET_LOGS    = (byte)0x40;
	    public static final byte CLEAR_LOGS	= (byte)0x41;
	    public static final byte REVOKE       = (byte)0x42; // See design.
	    public static final byte UPDATE_BALANCE_CHARGE = (byte)0x43;
	}
}
