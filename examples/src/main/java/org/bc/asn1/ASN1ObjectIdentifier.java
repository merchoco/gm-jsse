package org.bc.asn1;

public class ASN1ObjectIdentifier extends DERObjectIdentifier {
   public ASN1ObjectIdentifier(String var1) {
      super(var1);
   }

   ASN1ObjectIdentifier(byte[] var1) {
      super(var1);
   }

   public ASN1ObjectIdentifier branch(String var1) {
      return new ASN1ObjectIdentifier(this.getId() + "." + var1);
   }

   public boolean on(ASN1ObjectIdentifier var1) {
      String var2 = this.getId();
      String var3 = var1.getId();
      return var2.length() > var3.length() && var2.charAt(var3.length()) == '.' && var2.startsWith(var3);
   }
}
