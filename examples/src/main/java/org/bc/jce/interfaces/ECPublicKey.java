package org.bc.jce.interfaces;

import java.security.PublicKey;
import org.bc.math.ec.ECPoint;

public interface ECPublicKey extends ECKey, PublicKey {
   ECPoint getQ();
}
