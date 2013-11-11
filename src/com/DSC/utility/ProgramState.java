package com.DSC.utility;

import java.util.concurrent.ConcurrentHashMap;

import com.DSC.crypto.ISAACRandomGenerator;

public abstract class ProgramState
{
    public static boolean AUTHENTICATION_REQUEST;
    public static boolean AUTHENTICATED;
    public static boolean KEY_EXCHANGE_REQUEST;
    public static boolean KEY_RECEIVED;
    public static boolean AUTHENTICATION_DECISION;
    public static boolean AUTHENTICATION_ACKNOWLEDGE;
    public static String nick;
    public static ConcurrentHashMap<String, String> trustedKeys;
    public static String publicKey;
    public static String privateKey;
    public static String symmetricKey;
    public static String passphrase;
    public static ISAACRandomGenerator IVEngine;

}