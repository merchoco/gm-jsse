package org.bc.ocsp;

public interface OCSPRespStatus {
   int SUCCESSFUL = 0;
   int MALFORMED_REQUEST = 1;
   int INTERNAL_ERROR = 2;
   int TRY_LATER = 3;
   int SIGREQUIRED = 5;
   int UNAUTHORIZED = 6;
}
