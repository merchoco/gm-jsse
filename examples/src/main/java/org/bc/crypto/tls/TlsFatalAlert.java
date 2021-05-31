package org.bc.crypto.tls;

import java.io.IOException;

public class TlsFatalAlert extends IOException {
   private static final long serialVersionUID = 3584313123679111168L;
   private short alertDescription;

   public TlsFatalAlert(short var1) {
      this.alertDescription = var1;
   }

   public short getAlertDescription() {
      return this.alertDescription;
   }
}
