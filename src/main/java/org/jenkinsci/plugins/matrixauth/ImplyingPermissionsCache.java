package org.jenkinsci.plugins.matrixauth;

import hudson.security.Permission;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Caches implying permissions for fast future access.
 *
 * The cache is built up when this class is loaded.
 */
class ImplyingPermissionsCache {
    private static ConcurrentHashMap<Permission, Set<Permission>> implyingPermissionCache;

    static {
        implyingPermissionCache = new ConcurrentHashMap<>();
        Permission.getAll().forEach(ImplyingPermissionsCache::calculateAndCacheImplyingPermissions);
    }

    private static Set<Permission> calculateAndCacheImplyingPermissions(Permission perm) {
        Set<Permission> implyingPermissions = new HashSet<>();
        for (Permission p = perm; p != null; p = p.impliedBy) {
            implyingPermissions.add(p);
        }
        implyingPermissionCache.put(perm, implyingPermissions);
        return implyingPermissions;
    }

    private ImplyingPermissionsCache() {
    }

    /**
     * Returns the set of permissions that imply the permission {@code p}.
     *
     * @param p the permission
     * @return set of permissions that imply this permission
     */
    static Set<Permission> getImplyingPermissions(Permission p) {
        Set<Permission> permissions = implyingPermissionCache.get(p);
        if (permissions != null) {
            permissions = calculateAndCacheImplyingPermissions(p);
        }
        return permissions;
    }
}
