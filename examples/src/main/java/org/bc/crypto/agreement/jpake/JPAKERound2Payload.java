package org.bc.crypto.agreement.jpake;

import java.io.Serializable;
import java.math.BigInteger;
import org.bc.util.Arrays;

public class JPAKERound2Payload implements Serializable {
   private static final long serialVersionUID = 1L;
   private final String participantId;
   private final BigInteger a;
   private final BigInteger[] knowledgeProofForX2s;

   public JPAKERound2Payload(String var1, BigInteger var2, BigInteger[] var3) {
      JPAKEUtil.validateNotNull(var1, "participantId");
      JPAKEUtil.validateNotNull(var2, "a");
      JPAKEUtil.validateNotNull(var3, "knowledgeProofForX2s");
      this.participantId = var1;
      this.a = var2;
      this.knowledgeProofForX2s = Arrays.copyOf(var3, var3.length);
   }

   public String getParticipantId() {
      return this.participantId;
   }

   public BigInteger getA() {
      return this.a;
   }

   public BigInteger[] getKnowledgeProofForX2s() {
      return Arrays.copyOf(this.knowledgeProofForX2s, this.knowledgeProofForX2s.length);
   }
}
