package org.bc.crypto.agreement.jpake;

import java.io.Serializable;
import java.math.BigInteger;

public class JPAKERound3Payload implements Serializable {
   private static final long serialVersionUID = 1L;
   private final String participantId;
   private final BigInteger macTag;

   public JPAKERound3Payload(String var1, BigInteger var2) {
      this.participantId = var1;
      this.macTag = var2;
   }

   public String getParticipantId() {
      return this.participantId;
   }

   public BigInteger getMacTag() {
      return this.macTag;
   }
}
