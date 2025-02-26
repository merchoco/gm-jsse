package org.bc.asn1.x509;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;

public class UserNotice extends ASN1Object {
   private NoticeReference noticeRef;
   private DisplayText explicitText;

   public UserNotice(NoticeReference var1, DisplayText var2) {
      this.noticeRef = var1;
      this.explicitText = var2;
   }

   public UserNotice(NoticeReference var1, String var2) {
      this(var1, new DisplayText(var2));
   }

   private UserNotice(ASN1Sequence var1) {
      if (var1.size() == 2) {
         this.noticeRef = NoticeReference.getInstance(var1.getObjectAt(0));
         this.explicitText = DisplayText.getInstance(var1.getObjectAt(1));
      } else {
         if (var1.size() != 1) {
            throw new IllegalArgumentException("Bad sequence size: " + var1.size());
         }

         if (var1.getObjectAt(0).toASN1Primitive() instanceof ASN1Sequence) {
            this.noticeRef = NoticeReference.getInstance(var1.getObjectAt(0));
         } else {
            this.explicitText = DisplayText.getInstance(var1.getObjectAt(0));
         }
      }

   }

   public static UserNotice getInstance(Object var0) {
      if (var0 instanceof UserNotice) {
         return (UserNotice)var0;
      } else {
         return var0 != null ? new UserNotice(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   public NoticeReference getNoticeRef() {
      return this.noticeRef;
   }

   public DisplayText getExplicitText() {
      return this.explicitText;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      if (this.noticeRef != null) {
         var1.add(this.noticeRef);
      }

      if (this.explicitText != null) {
         var1.add(this.explicitText);
      }

      return new DERSequence(var1);
   }
}
