package cn.gmssl.sun.security.ssl;

import java.security.AccessControlContext;
import java.security.Permission;
import java.security.Principal;
import javax.crypto.SecretKey;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

public interface Krb5Proxy {
   Subject getClientSubject(AccessControlContext var1) throws LoginException;

   Subject getServerSubject(AccessControlContext var1) throws LoginException;

   SecretKey[] getServerKeys(AccessControlContext var1) throws LoginException;

   String getServerPrincipalName(SecretKey var1);

   String getPrincipalHostName(Principal var1);

   Permission getServicePermission(String var1, String var2);
}
