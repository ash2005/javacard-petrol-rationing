package ru.hwsec.teamara;

public final class Response {

	/* 	ERROR CODES  */
	// signal that the PIN verification failed
	final static short SW_VERIFICATION_FAILED = 0x6300;

	// signal the PIN validation is required
	// for a credit or a debit transaction
	final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	// signal invalid transaction amount
	// amount > MAX_TRANSACTION_MAOUNT or amount < 0
	final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;

	// signal the balance becomes negative
	final static short SW_NEGATIVE_BALANCE = 0x6A85;

	// ISSUED_STATE
	// Mutual Authentication

	// Checks

	// Petrol Terminal
	
	
	// Charging Terminal
}
