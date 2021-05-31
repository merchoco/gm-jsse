package cn.gmssl.crypto;

import cn.gmssl.crypto.impl.SM4Engine;
import org.bc.crypto.BlockCipher;
import org.bc.crypto.modes.CBCBlockCipher;
import org.bc.crypto.modes.CCMBlockCipher;
import org.bc.jcajce.provider.symmetric.util.BaseBlockCipher;

public class SM4JCE {
   public static class CBC extends BaseBlockCipher {
      public CBC() {
         super((BlockCipher)(new CBCBlockCipher(new SM4Engine())), 128);
      }
   }

   public static class CTR extends CCMBlockCipher {
      public CTR() {
         super(new SM4Engine());
      }
   }

   public static class ECB extends BaseBlockCipher {
      public ECB() {
         super(new SM4Engine());
      }
   }
}
