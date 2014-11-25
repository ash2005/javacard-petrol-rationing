package ru.hwsec.teamara;

public class Instruction {

    // INIT_STATE
    public static final byte SET_PRIV_KEY   = (byte)0x00;
    public static final byte SET_KEY_EXPIRY = (byte)0x01;
    public static final byte SET_SIGNATURE  = (byte)0x02;
    public static final byte SET_PIN        = (byte)0x03;
    public static final byte SET_BALANCE    = (byte)0x04;
    public static final byte CHECK_PIN      = (byte)0x05; // move under issued state.

    //ISSUED_STATE
    // Mutual Authentication
    public static final byte TERMINAL_HELLO = (byte)0x10;
    public static final byte TERMINAL_TYPE  = (byte)0x11;
    public static final byte TERMINAL_KEY   = (byte)0x12;
    public static final byte TERMINAL_KEY_SIGNATURE  = (byte)0x13;
    public static final byte TERMINAL_GET_CARD_KEY   = (byte)0x14;
    public static final byte TERMINAL_GET_CARD_EXPIRY       = (byte)0x15;
    public static final byte TERMINAL_GET_CARD_SIGNATURE    = (byte)0x16;
    public static final byte TERMINAL_CHANGE_CIPHER_SPEC    = (byte)0x17;


    // Checks

    // Petrol Terminal

    // Charging Terminal
    //

    private Instruction() { }
}
