package cn.gmssl.security.util;

import java.security.Permission;

public interface PermissionFactory<T extends Permission> {
   T newPermission(String var1);
}
