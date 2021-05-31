package cn.gmssl.crypto;

import cn.gmssl.crypto.impl.SM3;
import org.bc.jcajce.provider.digest.BCMessageDigest;

public class SM3Jce extends BCMessageDigest {
   public SM3Jce() {
      super(new SM3());
   }
}
