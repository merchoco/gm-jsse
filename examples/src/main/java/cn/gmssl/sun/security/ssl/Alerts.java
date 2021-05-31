package cn.gmssl.sun.security.ssl;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

final class Alerts {
   static final byte alert_warning = 1;
   static final byte alert_fatal = 2;
   static final byte alert_close_notify = 0;
   static final byte alert_unexpected_message = 10;
   static final byte alert_bad_record_mac = 20;
   static final byte alert_decryption_failed = 21;
   static final byte alert_record_overflow = 22;
   static final byte alert_decompression_failure = 30;
   static final byte alert_handshake_failure = 40;
   static final byte alert_no_certificate = 41;
   static final byte alert_bad_certificate = 42;
   static final byte alert_unsupported_certificate = 43;
   static final byte alert_certificate_revoked = 44;
   static final byte alert_certificate_expired = 45;
   static final byte alert_certificate_unknown = 46;
   static final byte alert_illegal_parameter = 47;
   static final byte alert_unknown_ca = 48;
   static final byte alert_access_denied = 49;
   static final byte alert_decode_error = 50;
   static final byte alert_decrypt_error = 51;
   static final byte alert_export_restriction = 60;
   static final byte alert_protocol_version = 70;
   static final byte alert_insufficient_security = 71;
   static final byte alert_internal_error = 80;
   static final byte alert_user_canceled = 90;
   static final byte alert_no_renegotiation = 100;
   static final byte alert_unsupported_extension = 110;
   static final byte alert_certificate_unobtainable = 111;
   static final byte alert_unrecognized_name = 112;
   static final byte alert_bad_certificate_status_response = 113;
   static final byte alert_bad_certificate_hash_value = 114;

   static String alertDescription(byte var0) {
      switch(var0) {
      case 0:
         return "close_notify";
      case 10:
         return "unexpected_message";
      case 20:
         return "bad_record_mac";
      case 21:
         return "decryption_failed";
      case 22:
         return "record_overflow";
      case 30:
         return "decompression_failure";
      case 40:
         return "handshake_failure";
      case 41:
         return "no_certificate";
      case 42:
         return "bad_certificate";
      case 43:
         return "unsupported_certificate";
      case 44:
         return "certificate_revoked";
      case 45:
         return "certificate_expired";
      case 46:
         return "certificate_unknown";
      case 47:
         return "illegal_parameter";
      case 48:
         return "unknown_ca";
      case 49:
         return "access_denied";
      case 50:
         return "decode_error";
      case 51:
         return "decrypt_error";
      case 60:
         return "export_restriction";
      case 70:
         return "protocol_version";
      case 71:
         return "insufficient_security";
      case 80:
         return "internal_error";
      case 90:
         return "user_canceled";
      case 100:
         return "no_renegotiation";
      case 110:
         return "unsupported_extension";
      case 111:
         return "certificate_unobtainable";
      case 112:
         return "unrecognized_name";
      case 113:
         return "bad_certificate_status_response";
      case 114:
         return "bad_certificate_hash_value";
      default:
         return "<UNKNOWN ALERT: " + (var0 & 255) + ">";
      }
   }

   static SSLException getSSLException(byte var0, String var1) {
      return getSSLException(var0, (Throwable)null, var1);
   }

   static SSLException getSSLException(byte var0, Throwable var1, String var2) {
      if (var2 == null) {
         if (var1 != null) {
            var2 = var1.toString();
         } else {
            var2 = "";
         }
      }

      Object var3;
      switch(var0) {
      case 0:
      case 10:
      case 20:
      case 21:
      case 22:
      case 30:
      case 47:
      case 50:
      case 70:
      case 80:
      case 90:
      case 100:
      default:
         var3 = new SSLException(var2);
         break;
      case 40:
      case 41:
      case 42:
      case 43:
      case 44:
      case 45:
      case 46:
      case 48:
      case 49:
      case 51:
      case 60:
      case 71:
      case 110:
      case 111:
      case 112:
      case 113:
      case 114:
         var3 = new SSLHandshakeException(var2);
      }

      if (var1 != null) {
         ((SSLException)var3).initCause(var1);
      }

      return (SSLException)var3;
   }
}
