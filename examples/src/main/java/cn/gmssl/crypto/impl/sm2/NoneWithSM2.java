package cn.gmssl.crypto.impl.sm2;

import org.bc.jcajce.provider.asymmetric.ec.BCSignatureSpi;

public class NoneWithSM2 extends BCSignatureSpi {
   public NoneWithSM2() {
      super(new NoneDigest(), new SM2Signer(), new StdDSAEncoder());
   }
}
