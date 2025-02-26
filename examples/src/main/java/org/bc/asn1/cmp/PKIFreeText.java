package org.bc.asn1.cmp;

import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERUTF8String;

public class PKIFreeText extends ASN1Object {
   ASN1Sequence strings;

   public static PKIFreeText getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static PKIFreeText getInstance(Object var0) {
      if (var0 instanceof PKIFreeText) {
         return (PKIFreeText)var0;
      } else {
         return var0 != null ? new PKIFreeText(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   private PKIFreeText(ASN1Sequence var1) {
      Enumeration var2 = var1.getObjects();

      while(var2.hasMoreElements()) {
         if (!(var2.nextElement() instanceof DERUTF8String)) {
            throw new IllegalArgumentException("attempt to insert non UTF8 STRING into PKIFreeText");
         }
      }

      this.strings = var1;
   }

   public PKIFreeText(DERUTF8String var1) {
      this.strings = new DERSequence(var1);
   }

   public PKIFreeText(String var1) {
      this(new DERUTF8String(var1));
   }

   public PKIFreeText(DERUTF8String[] var1) {
      this.strings = new DERSequence(var1);
   }

   public PKIFreeText(String[] var1) {
      ASN1EncodableVector var2 = new ASN1EncodableVector();

      for(int var3 = 0; var3 < var1.length; ++var3) {
         var2.add(new DERUTF8String(var1[var3]));
      }

      this.strings = new DERSequence(var2);
   }

   public int size() {
      return this.strings.size();
   }

   public DERUTF8String getStringAt(int var1) {
      return (DERUTF8String)this.strings.getObjectAt(var1);
   }

   public ASN1Primitive toASN1Primitive() {
      return this.strings;
   }
}
