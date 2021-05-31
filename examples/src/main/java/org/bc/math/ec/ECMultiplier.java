package org.bc.math.ec;

import java.math.BigInteger;

interface ECMultiplier {
   ECPoint multiply(ECPoint var1, BigInteger var2, PreCompInfo var3);
}
