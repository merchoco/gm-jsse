package org.bc.jce.interfaces;

import java.math.BigInteger;
import java.security.PrivateKey;

public interface ElGamalPrivateKey extends ElGamalKey, PrivateKey {
   BigInteger getX();
}
