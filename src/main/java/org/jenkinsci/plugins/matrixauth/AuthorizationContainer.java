/*
 * The MIT License
 *
 * Copyright (c) 2004-2017 Sun Microsystems, Inc., Kohsuke Kawaguchi, Yahoo! Inc., Peter Hayes, Tom Huybrechts, Daniel Beck
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.matrixauth;

import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.SecurityRealm;
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

@Restricted(NoExternalUse.class)
public interface AuthorizationContainer {

    @Restricted(NoExternalUse.class)
    class IdStrategyComparator implements Comparator<String> {
        private final SecurityRealm securityRealm = Jenkins.getInstance().getSecurityRealm();
        private final IdStrategy groupIdStrategy = securityRealm.getGroupIdStrategy();
        private final IdStrategy userIdStrategy = securityRealm.getUserIdStrategy();

        public int compare(String o1, String o2) {
            int r = userIdStrategy.compare(o1, o2);
            if (r == 0) {
                r = groupIdStrategy.compare(o1, o2);
            }
            return r;
        }
    }

    void add(Permission permission, String sid);
    Map<Permission, Set<String>> getGrantedPermissions();

    /**
     * Works like {@link #add(Permission, String)} but takes both parameters
     * from a single string of the form <tt>PERMISSIONID:sid</tt>
     */
    @Restricted(NoExternalUse.class)
    default void add(String shortForm) {
        int idx = shortForm.indexOf(':');
        Permission p = Permission.fromId(shortForm.substring(0, idx));
        if (p==null)
            throw new IllegalArgumentException("Failed to parse '"+shortForm+"' --- no such permission");
        add(p, shortForm.substring(idx + 1));
    }

    /**
     * Returns all SIDs configured in this matrix, minus "anonymous"
     *
     * @return Always non-null.
     */
    default List<String> getAllSIDs() {
        Set<String> r = new TreeSet<>(new GlobalMatrixAuthorizationStrategy.IdStrategyComparator());
        for (Set<String> set : getGrantedPermissions().values())
            r.addAll(set);
        r.remove("anonymous");

        String[] data = r.toArray(new String[r.size()]);
        Arrays.sort(data);
        return Arrays.asList(data);
    }

    @Restricted(NoExternalUse.class)
    default boolean isAnyRelevantDangerousPermissionExplicitlyGranted() {
        for (String sid : getAllSIDs()) {
            if (isAnyRelevantDangerousPermissionExplicitlyGranted(sid)) {
                return true;
            }
        }
        return isAnyRelevantDangerousPermissionExplicitlyGranted("anonymous");
    }

    @Restricted(NoExternalUse.class)
    default boolean isAnyRelevantDangerousPermissionExplicitlyGranted(String sid) {
        for (Permission p : GlobalMatrixAuthorizationStrategy.DANGEROUS_PERMISSIONS) {
            if (!hasPermission(sid, Jenkins.ADMINISTER) && hasExplicitPermission(sid, p)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the given SID has the given permission.
     */
    default boolean hasPermission(String sid, Permission p) {
        if (!GlobalMatrixAuthorizationStrategy.ENABLE_DANGEROUS_PERMISSIONS
                && GlobalMatrixAuthorizationStrategy.DANGEROUS_PERMISSIONS.contains(p)) {
            return hasPermission(sid, Jenkins.ADMINISTER);
        }
        final SecurityRealm securityRealm = Jenkins.getInstance().getSecurityRealm();
        final IdStrategy groupIdStrategy = securityRealm.getGroupIdStrategy();
        final IdStrategy userIdStrategy = securityRealm.getUserIdStrategy();
        for (; p != null; p = p.impliedBy) {
            if (!p.getEnabled()) {
                continue;
            }
            Set<String> set = getGrantedPermissions().get(p);
            if (set == null) {
                continue;
            }
            if (set.contains(sid)) {
                return true;
            }
            for (String s: set) {
                if (userIdStrategy.equals(s, sid) || groupIdStrategy.equals(s, sid)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks if the given SID has the given permission.
     */
    default boolean hasPermission(String sid, Permission p, boolean principal) {
        if (!GlobalMatrixAuthorizationStrategy.ENABLE_DANGEROUS_PERMISSIONS
                && GlobalMatrixAuthorizationStrategy.DANGEROUS_PERMISSIONS.contains(p)) {
            return hasPermission(sid, Jenkins.ADMINISTER, principal);
        }
        final SecurityRealm securityRealm = Jenkins.getInstance().getSecurityRealm();
        final IdStrategy strategy = principal ? securityRealm.getUserIdStrategy() : securityRealm.getGroupIdStrategy();
        for (; p != null; p = p.impliedBy) {
            if (!p.getEnabled()) {
                continue;
            }
            Set<String> set = getGrantedPermissions().get(p);
            if (set == null) {
                continue;
            }
            if (set.contains(sid)) {
                return true;
            }
            for (String s : set) {
                if (strategy.equals(s, sid)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks if the permission is explicitly given, instead of implied through {@link Permission#impliedBy}.
     */
    default boolean hasExplicitPermission(String sid, Permission p) {
        if (sid == null) { // used for template row in UI
            return false;
        }
        Set<String> set = getGrantedPermissions().get(p);
        if (set != null && p.getEnabled()) {
            if (set.contains(sid))
                return true;
            final SecurityRealm securityRealm = Jenkins.getInstance().getSecurityRealm();
            final IdStrategy groupIdStrategy = securityRealm.getGroupIdStrategy();
            final IdStrategy userIdStrategy = securityRealm.getUserIdStrategy();
            for (String s: set) {
                if (userIdStrategy.equals(s, sid) || groupIdStrategy.equals(s, sid)) {
                    return true;
                }
            }
        }
        return false;
    }

}
