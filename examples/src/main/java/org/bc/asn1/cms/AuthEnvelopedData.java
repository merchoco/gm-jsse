package org.bc.asn1.cms;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1Set;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.BERSequence;
import org.bc.asn1.DERTaggedObject;

public class AuthEnvelopedData extends ASN1Object {
   private ASN1Integer version;
   private OriginatorInfo originatorInfo;
   private ASN1Set recipientInfos;
   private EncryptedContentInfo authEncryptedContentInfo;
   private ASN1Set authAttrs;
   private ASN1OctetString mac;
   private ASN1Set unauthAttrs;

   public AuthEnvelopedData(OriginatorInfo var1, ASN1Set var2, EncryptedContentInfo var3, ASN1Set var4, ASN1OctetString var5, ASN1Set var6) {
      this.version = new ASN1Integer(0L);
      this.originatorInfo = var1;
      this.recipientInfos = var2;
      this.authEncryptedContentInfo = var3;
      this.authAttrs = var4;
      this.mac = var5;
      this.unauthAttrs = var6;
   }

   public AuthEnvelopedData(ASN1Sequence var1) {
      byte var2 = 0;
      int var4 = var2 + 1;
      ASN1Primitive var3 = var1.getObjectAt(var2).toASN1Primitive();
      this.version = (ASN1Integer)var3;
      var3 = var1.getObjectAt(var4++).toASN1Primitive();
      if (var3 instanceof ASN1TaggedObject) {
         this.originatorInfo = OriginatorInfo.getInstance((ASN1TaggedObject)var3, false);
         var3 = var1.getObjectAt(var4++).toASN1Primitive();
      }

      this.recipientInfos = ASN1Set.getInstance(var3);
      var3 = var1.getObjectAt(var4++).toASN1Primitive();
      this.authEncryptedContentInfo = EncryptedContentInfo.getInstance(var3);
      var3 = var1.getObjectAt(var4++).toASN1Primitive();
      if (var3 instanceof ASN1TaggedObject) {
         this.authAttrs = ASN1Set.getInstance((ASN1TaggedObject)var3, false);
         var3 = var1.getObjectAt(var4++).toASN1Primitive();
      }

      this.mac = ASN1OctetString.getInstance(var3);
      if (var1.size() > var4) {
         var3 = var1.getObjectAt(var4++).toASN1Primitive();
         this.unauthAttrs = ASN1Set.getInstance((ASN1TaggedObject)var3, false);
      }

   }

   public static AuthEnvelopedData getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static AuthEnvelopedData getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof AuthEnvelopedData)) {
         if (var0 instanceof ASN1Sequence) {
            return new AuthEnvelopedData((ASN1Sequence)var0);
         } else {
            throw new IllegalArgumentException("Invalid AuthEnvelopedData: " + var0.getClass().getName());
         }
      } else {
         return (AuthEnvelopedData)var0;
      }
   }

   public ASN1Integer getVersion() {
      return this.version;
   }

   public OriginatorInfo getOriginatorInfo() {
      return this.originatorInfo;
   }

   public ASN1Set getRecipientInfos() {
      return this.recipientInfos;
   }

   public EncryptedContentInfo getAuthEncryptedContentInfo() {
      return this.authEncryptedContentInfo;
   }

   public ASN1Set getAuthAttrs() {
      return this.authAttrs;
   }

   public ASN1OctetString getMac() {
      return this.mac;
   }

   public ASN1Set getUnauthAttrs() {
      return this.unauthAttrs;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.version);
      if (this.originatorInfo != null) {
         var1.add(new DERTaggedObject(false, 0, this.originatorInfo));
      }

      var1.add(this.recipientInfos);
      var1.add(this.authEncryptedContentInfo);
      if (this.authAttrs != null) {
         var1.add(new DERTaggedObject(false, 1, this.authAttrs));
      }

      var1.add(this.mac);
      if (this.unauthAttrs != null) {
         var1.add(new DERTaggedObject(false, 2, this.unauthAttrs));
      }

      return new BERSequence(var1);
   }
}
