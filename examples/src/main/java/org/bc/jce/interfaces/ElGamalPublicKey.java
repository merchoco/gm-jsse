package org.bc.jce.interfaces;

import java.math.BigInteger;
import java.security.PublicKey;

public interface ElGamalPublicKey extends ElGamalKey, PublicKey {
   BigInteger getY();
}
