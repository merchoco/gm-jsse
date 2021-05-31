package org.bc.asn1.cms;

import java.io.IOException;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1OctetStringParser;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1SequenceParser;
import org.bc.asn1.BERSequence;
import org.bc.asn1.DERIA5String;

public class TimeStampedDataParser {
   private ASN1Integer version;
   private DERIA5String dataUri;
   private MetaData metaData;
   private ASN1OctetStringParser content;
   private Evidence temporalEvidence;
   private ASN1SequenceParser parser;

   private TimeStampedDataParser(ASN1SequenceParser var1) throws IOException {
      this.parser = var1;
      this.version = ASN1Integer.getInstance(var1.readObject());
      ASN1Encodable var2 = var1.readObject();
      if (var2 instanceof DERIA5String) {
         this.dataUri = DERIA5String.getInstance(var2);
         var2 = var1.readObject();
      }

      if (var2 instanceof MetaData || var2 instanceof ASN1SequenceParser) {
         this.metaData = MetaData.getInstance(var2.toASN1Primitive());
         var2 = var1.readObject();
      }

      if (var2 instanceof ASN1OctetStringParser) {
         this.content = (ASN1OctetStringParser)var2;
      }

   }

   public static TimeStampedDataParser getInstance(Object var0) throws IOException {
      if (var0 instanceof ASN1Sequence) {
         return new TimeStampedDataParser(((ASN1Sequence)var0).parser());
      } else {
         return var0 instanceof ASN1SequenceParser ? new TimeStampedDataParser((ASN1SequenceParser)var0) : null;
      }
   }

   public DERIA5String getDataUri() {
      return this.dataUri;
   }

   public MetaData getMetaData() {
      return this.metaData;
   }

   public ASN1OctetStringParser getContent() {
      return this.content;
   }

   public Evidence getTemporalEvidence() throws IOException {
      if (this.temporalEvidence == null) {
         this.temporalEvidence = Evidence.getInstance(this.parser.readObject().toASN1Primitive());
      }

      return this.temporalEvidence;
   }

   /** @deprecated */
   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.version);
      if (this.dataUri != null) {
         var1.add(this.dataUri);
      }

      if (this.metaData != null) {
         var1.add(this.metaData);
      }

      if (this.content != null) {
         var1.add(this.content);
      }

      var1.add(this.temporalEvidence);
      return new BERSequence(var1);
   }
}
