/**
 * Distributed Secure Channel
 * A novel distributed cryptosystem based on the concepts of PGP and Bitcoin.
 *
 * Copyright (C) 2013, Jonathan Gillett, Joseph Heron, and Daniel Smullen
 * All rights reserved.
 *
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
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