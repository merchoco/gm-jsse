package org.bc.crypto.engines;

public class CamelliaWrapEngine extends RFC3394WrapEngine {
   public CamelliaWrapEngine() {
      super(new CamelliaEngine());
   }
}
