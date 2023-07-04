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

import hudson.init.InitMilestone;
import hudson.model.Descriptor;
import hudson.security.AuthorizationStrategy;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.SecurityRealm;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.integrations.PermissionFinder;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Restricted(NoExternalUse.class)
public interface AuthorizationContainer {

    Logger LOGGER = Logger.getLogger(AuthorizationContainer.class.getName());

    @Restricted(NoExternalUse.class)
    class IdStrategyComparator implements Comparator<String> {
        private final SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
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

    /**
     * @since 3.0
     */
    @Restricted(NoExternalUse.class)
    class PermissionEntryComparator implements Comparator<PermissionEntry> {
        private final SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
        private final IdStrategy groupIdStrategy = securityRealm.getGroupIdStrategy();
        private final IdStrategy userIdStrategy = securityRealm.getUserIdStrategy();
        private final IdStrategyComparator eitherComparator = new IdStrategyComparator();

        @Override
        public int compare(PermissionEntry o1, PermissionEntry o2) {
            int r = o1.getType().compareTo(o2.getType());
            if (r != 0) {
                return r;
            }
            switch (o1.getType()) {
                case USER:
                    return userIdStrategy.compare(o1.getSid(), o2.getSid());
                case GROUP:
                    return groupIdStrategy.compare(o1.getSid(), o2.getSid());
                case EITHER:
                    return eitherComparator.compare(o1.getSid(), o2.getSid());
                default:
                    throw new IllegalArgumentException("Unexpected arguments o1: " + o1 + ", o2: " + o2);
            }
        }
    }

    /**
     * @deprecated Since 3.0, use {@link #add(Permission, PermissionEntry)} instead.
     */
    @Deprecated
    default void add(Permission permission, String sid) {
        DeprecationUtil.logDeprecationMessage();
        add(permission, new PermissionEntry(AuthorizationType.EITHER, sid));
    }

    /**
     * Adds to {@link #getGrantedPermissionEntries()}. Use of this method should be limited
     * during construction, as this object itself is considered immutable once
     * populated.
     *
     * @since 3.0
     */
    default void add(Permission permission, PermissionEntry entry) {
        if (permission == null) {
            throw new IllegalArgumentException("Permission cannot be null for: " + entry);
        }

        LOGGER.log(Level.FINE, "Grant permission \"{0}\" to \"{1}\")", new Object[] {permission, entry});
        getGrantedPermissionEntries()
                .computeIfAbsent(permission, k -> new HashSet<>())
                .add(entry);
        if (entry.getType() != AuthorizationType.USER) {
            recordGroup(entry.getSid());
        }
    }

    /**
     * Returns all the (Permission, sid) tuples where permissions are granted to either
     * groups or users. This does NOT include permissions granted specifically to users or groups (added in 3.0).
     *
     * @return read-only. never null.
     * @deprecated Since 3.0, use {{@link #getGrantedPermissionEntries()}} instead.
     */
    @Deprecated
    default Map<Permission, Set<String>> getGrantedPermissions() {
        DeprecationUtil.logDeprecationMessage();
        final Map<Permission, Set<String>> ret = new HashMap<>();
        final Map<Permission, Set<PermissionEntry>> grantedPermissionEntries = getGrantedPermissionEntries();
        for (Map.Entry<Permission, Set<PermissionEntry>> entry : grantedPermissionEntries.entrySet()) {
            final Set<String> eitherGrants = entry.getValue().stream()
                    .filter(it -> it.getType() == AuthorizationType.EITHER)
                    .map(PermissionEntry::getSid)
                    .collect(Collectors.toSet());
            if (eitherGrants.size() > 0) {
                ret.put(entry.getKey(), eitherGrants);
            }
        }
        return ret;
    }

    /**
     * Returns a live modifiable map of permissions. This return value needs to
     * be treated as unmodifiable from shortly after object construction (even
     * though it isn't for practical reasons).
     *
     * @since 3.0
     */
    Map<Permission, Set<PermissionEntry>> getGrantedPermissionEntries();

    /**
     * Internal only: Returns all recorded (possible) group sids to allow populating {@link AuthorizationStrategy#getGroups()}.
     *
     * @since 3.0
     */
    Set<String> getGroups();

    /**
     * Internal only: Record use of a (possible) group sid to be later returned in {@link #getGroups()}.
     */
    void recordGroup(String sid);

    @SuppressWarnings("rawtypes")
    Descriptor getDescriptor();

    /**
     * Works like {@link #add(Permission, PermissionEntry)} but takes both parameters
     * from a single string of the form <code>PERMISSION_ID:sid</code> (legacy format, implicit 'EITHER' type)
     * or <code>type:PERMISSION_ID:sid</code> (new since 3.0).
     * <p>The supported formats for <code>PERMISSION_ID</code> are:</p>
     * <ul>
     *     <li>Internal ID: <code>hudson.model.Hudson.ADMINISTER</code></li>
     *     <li>UI short form: <code>Overall/Administer</code></li>
     * </ul>
     * @see hudson.security.Permission#fromId(String)
     * @see org.jenkinsci.plugins.matrixauth.integrations.PermissionFinder
     */
    @Restricted(NoExternalUse.class)
    default void add(String shortForm) {
        AuthorizationType type;
        int firstEndIndex = shortForm.indexOf(':');
        String first = shortForm.substring(0, firstEndIndex);
        String permissionString;
        String sid;
        try {
            // attempt parsing new style format
            type = AuthorizationType.valueOf(first);
            final int permissionEndIndex = shortForm.indexOf(':', first.length() + 1);
            permissionString = shortForm.substring(firstEndIndex + 1, permissionEndIndex);
            sid = shortForm.substring(permissionEndIndex + 1);
        } catch (IllegalArgumentException ex) {
            // fall back to legacy format
            type = AuthorizationType.EITHER;
            permissionString = first;
            sid = shortForm.substring(firstEndIndex + 1);
            LOGGER.log(
                    Jenkins.get().getInitLevel().ordinal() < InitMilestone.COMPLETED.ordinal()
                            ? Level.WARNING
                            : Level.FINE,
                    "Processing a permission assignment in the legacy format (without explicit TYPE prefix): "
                            + shortForm);
        }
        Permission p = parsePermission(permissionString);
        if (!p.isContainedBy(((AuthorizationContainerDescriptor) getDescriptor()).getPermissionScope())) {
            LOGGER.log(
                    Level.WARNING,
                    "Tried to add inapplicable permission " + p + " for " + sid + " in " + this + ", skipping");
            return;
        }
        add(p, new PermissionEntry(type, sid));
    }

    @Restricted(NoExternalUse.class)
    static Permission parsePermission(String permission) {
        Permission p = Permission.fromId(permission);
        if (p == null) {
            // attempt to find the permission based on the 'nice' name, e.g. Overall/Administer
            p = PermissionFinder.findPermission(permission);
        }
        if (p == null) {
            throw new IllegalArgumentException("Failed to parse '" + permission + "' --- no such permission");
        }
        return p;
    }

    @Restricted(NoExternalUse.class)
    @SuppressWarnings("unused") // used from Jelly
    Permission getEditingPermission();

    /**
     * Returns SIDs configured in this matrix with 'either' (legacy pre-3.0) type, minus "anonymous".
     * This does NOT include permissions granted specifically to users or groups (new in 3.0).
     *
     * @return Always non-null.
     *
     * @deprecated Since 3.0, use {{@link #getAllPermissionEntries()}} instead.
     */
    @Deprecated
    default List<String> getAllSIDs() {
        DeprecationUtil.logDeprecationMessage();
        Set<String> r = new TreeSet<>(new GlobalMatrixAuthorizationStrategy.IdStrategyComparator());
        for (Set<String> set : getGrantedPermissions().values()) r.addAll(set);
        r.remove("anonymous");

        String[] data = r.toArray(new String[0]);
        Arrays.sort(data);
        return Arrays.asList(data);
    }

    default List<PermissionEntry> getAllPermissionEntries() {
        Set<PermissionEntry> entries = new TreeSet<>(new PermissionEntryComparator());
        for (Set<PermissionEntry> s : getGrantedPermissionEntries().values()) {
            entries.addAll(s);
        }
        entries.remove(new PermissionEntry(AuthorizationType.USER, "anonymous"));

        return new ArrayList<>(entries);
    }

    /**
     * Checks if the given SID has the given permission.
     *
     * @deprecated Use {@link #hasPermission(String, Permission, boolean)} instead.
     */
    @Deprecated
    default boolean hasPermission(String sid, Permission p) {
        final SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
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
            for (String s : set) {
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
        final SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
        final IdStrategy strategy = principal ? securityRealm.getUserIdStrategy() : securityRealm.getGroupIdStrategy();
        for (; p != null; p = p.impliedBy) {
            if (!p.getEnabled()) {
                continue;
            }
            Set<PermissionEntry> set = getGrantedPermissionEntries().get(p);
            if (set == null) {
                continue;
            }
            if (set.contains(new PermissionEntry(AuthorizationType.EITHER, sid))) {
                return true;
            }
            if (set.contains(new PermissionEntry(principal ? AuthorizationType.USER : AuthorizationType.GROUP, sid))) {
                return true;
            }
            for (PermissionEntry entry : set) {
                if (entry.isApplicable(principal) && strategy.equals(entry.getSid(), sid)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks if the permission is explicitly given, instead of implied through {@link Permission#impliedBy}.
     */
    @Deprecated
    default boolean hasExplicitPermission(String sid, Permission p) {
        DeprecationUtil.logDeprecationMessage();
        for (AuthorizationType type : AuthorizationType.values()) {
            if (hasExplicitPermission(new PermissionEntry(type, sid), p)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return true if and only if the exact permission entry is explicitly granted the specified permission,
     * ignoring compatible types (e.g. passing USER will not match an EITHER entry) and implications.
     * @param entry the entry to check for
     * @param p the permission to check for
     * @return true if and only if the exact entry matches
     *
     * @since 3.0
     */
    default boolean hasExplicitPermission(PermissionEntry entry, Permission p) {
        if (entry == null) { // used for template row in UI
            return false;
        }
        Set<PermissionEntry> grantedEntries = getGrantedPermissionEntries().get(p);
        if (grantedEntries != null && p.getEnabled()) {
            if (grantedEntries.contains(entry)) {
                return true;
            }
            final SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
            final IdStrategy groupIdStrategy = securityRealm.getGroupIdStrategy();
            final IdStrategy userIdStrategy = securityRealm.getUserIdStrategy();
            for (PermissionEntry s : grantedEntries) {
                if (s.getType() != entry.getType()) {
                    // only match if the type provided is identical
                    continue;
                }
                if (userIdStrategy.equals(s.getSid(), entry.getSid())
                        || groupIdStrategy.equals(s.getSid(), entry.getSid())) {
                    return true;
                }
            }
        }
        return false;
    }
}
