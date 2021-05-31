package cn.gmssl.crypto;

import cn.gmssl.crypto.impl.SM3;
import org.bc.crypto.macs.HMac;
import org.bc.jce.provider.JCEMac;

public class HMacSM3 extends JCEMac {
   public HMacSM3() {
      super(new HMac(new SM3()));
   }
}
