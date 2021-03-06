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

import java.io.BufferedReader;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.jgroups.Address;
import org.jgroups.JChannel;
import org.joda.time.format.DateTimeFormatter;

import com.DSC.crypto.ISAACRandomGenerator;
import com.google.common.collect.ConcurrentHashMultiset;

public abstract class ProgramState
{
    /* Program message handling states */
    public volatile static boolean AUTHENTICATION_REQUEST = false;
    public volatile static boolean AUTHENTICATED = false;
    public volatile static boolean KEY_EXCHANGE_REQUEST = false;
    public volatile static boolean KEY_RECEIVED = false;
    public volatile static boolean AUTHENTICATION_DECISION = false;
    public volatile static boolean AUTHENTICATION_ACKNOWLEDGE = false;
    
    /* Channel */
    public volatile static JChannel channel;
    public volatile static String nick;
    
    /* Input handling */
    public volatile static BufferedReader in;
    public volatile static InputSymbol symbol = new InputSymbol();
    
    /* Channel security: trusted keys, blacklist, and network keys */
    public volatile static ConcurrentHashMap<String, Address> trustedKeys;
    public volatile static ConcurrentHashMultiset<Address> blacklist;
    public volatile static ECPublicKeyParameters publicKey;
    public volatile static ECPrivateKeyParameters privateKey;
    public volatile static byte[] symmetricKey;
    public volatile static String passphrase;
    public volatile static ISAACRandomGenerator IVEngine;
    
    /* Network time */
    public volatile static DateTimeFormatter fmt;
}