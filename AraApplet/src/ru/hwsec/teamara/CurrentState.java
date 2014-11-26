package ru.hwsec.teamara;

public class CurrentState {

    public static final byte ZERO           = (byte)0;
    public static final byte HELLO          = (byte)1;
    public static final byte KEY_EXCHANGE   = (byte)2;
    public static final byte CHANGE_CIPHER   = (byte)3;

    private CurrentState() { }
}
