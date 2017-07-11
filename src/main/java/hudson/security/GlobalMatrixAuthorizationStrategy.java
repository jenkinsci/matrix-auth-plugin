/*
 * The MIT License
 * 
 * Copyright (c) 2004-2010, Sun Microsystems, Inc., Kohsuke Kawaguchi, Yahoo! Inc.
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
package hudson.security;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.PluginManager;
import hudson.diagnosis.OldDataMonitor;
import hudson.model.Descriptor;
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.FormValidation.Kind;
import hudson.util.VersionNumber;
import hudson.util.RobustReflectionConverter;
import hudson.Functions;
import hudson.Extension;
import hudson.model.User;
import net.sf.json.JSONObject;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.acls.sid.Sid;
import org.jenkinsci.plugins.matrixauth.Messages;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;
import org.springframework.dao.DataAccessException;

import javax.servlet.ServletException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.IOException;
import java.util.Collections;
import java.util.SortedMap;
import java.util.TreeMap;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

/**
 * Role-based authorization via a matrix.
 *
 * @author Kohsuke Kawaguchi
 */
// TODO: think about the concurrency commitment of this class
public class GlobalMatrixAuthorizationStrategy extends AuthorizationStrategy {
    private transient SidACL acl = new AclImpl();

    /**
     * List up all permissions that are granted.
     *
     * Strings are either the granted authority or the principal,
     * which is not distinguished.
     */
    private final Map<Permission,Set<String>> grantedPermissions = new HashMap<Permission, Set<String>>();

    /**
     * List of permissions considered dangerous to grant to non-admin users
     */
    @Restricted(NoExternalUse.class)
    static final List<Permission> DANGEROUS_PERMISSIONS = Arrays.asList(
            Jenkins.RUN_SCRIPTS,
            PluginManager.CONFIGURE_UPDATECENTER,
            PluginManager.UPLOAD_PLUGINS
    );

    private final Set<String> sids = new HashSet<String>();

    /**
     * Adds to {@link #grantedPermissions}.
     * Use of this method should be limited during construction,
     * as this object itself is considered immutable once populated.
     */
    public void add(Permission p, String sid) {
        if (p==null)
            throw new IllegalArgumentException("Permission can not be null for sid:" + sid);

        LOGGER.log(Level.FINE, "Grant permission \"{0}\" to \"{1}\")", new Object[]{p, sid});
        Set<String> set = grantedPermissions.get(p);
        if(set==null)
            grantedPermissions.put(p,set = new HashSet<String>());
        set.add(sid);
        sids.add(sid);
    }

    /**
     * Works like {@link #add(Permission, String)} but takes both parameters
     * from a single string of the form <tt>PERMISSIONID:sid</tt>
     */
    private void add(String shortForm) {
        int idx = shortForm.indexOf(':');
        Permission p = Permission.fromId(shortForm.substring(0, idx));
        if (p==null)
            throw new IllegalArgumentException("Failed to parse '"+shortForm+"' --- no such permission");
        add(p,shortForm.substring(idx+1));
    }

    @Override
    public ACL getRootACL() {
        return acl;
    }

    public Set<String> getGroups() {
        final TreeSet<String> sids = new TreeSet<String>(new IdStrategyComparator());
        sids.addAll(this.sids);
        return sids;
    }

    /**
     * Due to HUDSON-2324, we want to inject Item.READ permission to everyone who has Hudson.READ,
     * to remain backward compatible.
     * @param grantedPermissions
     */
    /*package*/ static boolean migrateHudson2324(Map<Permission,Set<String>> grantedPermissions) {
        boolean result = false;
        if(Jenkins.getActiveInstance().isUpgradedFromBefore(new VersionNumber("1.300.*"))) {
            Set<String> f = grantedPermissions.get(Jenkins.READ);
            if (f!=null) {
                Set<String> t = grantedPermissions.get(Item.READ);
                if (t!=null)
                    result = t.addAll(f);
                else {
                    t = new HashSet<String>(f);
                    result = true;
                }
                grantedPermissions.put(Item.READ,t);
            }
        }
        return result;
    }

    /**
     * Checks if the given SID has the given permission.
     */
    public boolean hasPermission(String sid, Permission p) {
        if (!ENABLE_DANGEROUS_PERMISSIONS && DANGEROUS_PERMISSIONS.contains(p)) {
            return hasPermission(sid, Jenkins.ADMINISTER);
        }
        final SecurityRealm securityRealm = Jenkins.getActiveInstance().getSecurityRealm();
        final IdStrategy groupIdStrategy = securityRealm.getGroupIdStrategy();
        final IdStrategy userIdStrategy = securityRealm.getUserIdStrategy();
        for (; p != null; p = p.impliedBy) {
            if (!p.getEnabled()) {
                continue;
            }
            Set<String> set = grantedPermissions.get(p);
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
    public boolean hasPermission(String sid, Permission p, boolean principal) {
        final SecurityRealm securityRealm = Jenkins.getActiveInstance().getSecurityRealm();
        final IdStrategy strategy = principal ? securityRealm.getUserIdStrategy() : securityRealm.getGroupIdStrategy();
        for (; p != null; p = p.impliedBy) {
            if (!p.getEnabled()) {
                continue;
            }
            Set<String> set = grantedPermissions.get(p);
            if (set != null && set.contains(sid)) {
                return true;
            }
            if (set != null) {
                for (String s : set) {
                    if (strategy.equals(s, sid)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Checks if the permission is explicitly given, instead of implied through {@link Permission#impliedBy}.
     */
    public boolean hasExplicitPermission(String sid, Permission p) {
        Set<String> set = grantedPermissions.get(p);
        if (set != null && p.getEnabled()) {
            if (set.contains(sid)) {
                return true;
            }
            final SecurityRealm securityRealm = Jenkins.getActiveInstance().getSecurityRealm();
            final IdStrategy groupIdStrategy = securityRealm.getGroupIdStrategy();
            final IdStrategy userIdStrategy = securityRealm.getUserIdStrategy();
            for (String s : set) {
                if (userIdStrategy.equals(s, sid) || groupIdStrategy.equals(s, sid)) {
                    return true;
                }
            }
        }
        return false;
    }

    boolean isAnyRelevantDangerousPermissionExplicitlyGranted() {
        for (String sid : getAllSIDs()) {
            if (isAnyRelevantDangerousPermissionExplicitlyGranted(sid)) {
                return true;
            }
        }
        if (isAnyRelevantDangerousPermissionExplicitlyGranted("anonymous")) {
            return true;
        }
        return false;
    }

    boolean isAnyRelevantDangerousPermissionExplicitlyGranted(String sid) {
        for (Permission p : DANGEROUS_PERMISSIONS) {
            if (!hasPermission(sid, Jenkins.ADMINISTER) && hasExplicitPermission(sid, p)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns all SIDs configured in this matrix, minus "anonymous"
     *
     * @return
     *      Always non-null.
     */
    public List<String> getAllSIDs() {
        Set<String> r = new TreeSet<String>(new IdStrategyComparator());
        for (Set<String> set : grantedPermissions.values())
            r.addAll(set);
        r.remove("anonymous");

        String[] data = r.toArray(new String[r.size()]);
        Arrays.sort(data);
        return Arrays.asList(data);
    }

    /*package*/ static class IdStrategyComparator implements Comparator<String> {
        private final SecurityRealm securityRealm = Jenkins.getActiveInstance().getSecurityRealm();
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

    private final class AclImpl extends SidACL {
        @CheckForNull
        @SuppressFBWarnings(value = "NP_BOOLEAN_RETURN_NULL", 
                        justification = "As designed, implements a third state for the ternary logic")
        protected Boolean hasPermission(Sid p, Permission permission) {
            if(GlobalMatrixAuthorizationStrategy.this.hasPermission(toString(p),permission, p instanceof PrincipalSid))
                return true;
            return null;
        }
    }

    @Extension
    public static final DescriptorImpl DESCRIPTOR = new DescriptorImpl();

    /**
     * Persist {@link GlobalMatrixAuthorizationStrategy} as a list of IDs that
     * represent {@link GlobalMatrixAuthorizationStrategy#grantedPermissions}.
     */
    public static class ConverterImpl implements Converter {
        public boolean canConvert(Class type) {
            return type==GlobalMatrixAuthorizationStrategy.class;
        }

        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
            final IdStrategyComparator comparator = new IdStrategyComparator();
            GlobalMatrixAuthorizationStrategy strategy = (GlobalMatrixAuthorizationStrategy)source;

            // Output in alphabetical order for readability.
            SortedMap<Permission, Set<String>> sortedPermissions = new TreeMap<Permission, Set<String>>(Permission.ID_COMPARATOR);
            sortedPermissions.putAll(strategy.grantedPermissions);
            for (Entry<Permission, Set<String>> e : sortedPermissions.entrySet()) {
                String p = e.getKey().getId();
                Set<String> sids = new TreeSet<String>(comparator);
                sids.addAll(e.getValue());
                for (String sid : sids) {
                    writer.startNode("permission");
                    writer.setValue(p+':'+sid);
                    writer.endNode();
                }
            }

        }

        public Object unmarshal(HierarchicalStreamReader reader, final UnmarshallingContext context) {
            GlobalMatrixAuthorizationStrategy as = create();

            while (reader.hasMoreChildren()) {
                reader.moveDown();
                try {
                    as.add(reader.getValue());
                } catch (IllegalArgumentException ex) {
                    Logger.getLogger(GlobalMatrixAuthorizationStrategy.class.getName())
                          .log(Level.WARNING,"Skipping a non-existent permission",ex);
                    RobustReflectionConverter.addErrorInContext(context, ex);
                }
                reader.moveUp();
            }

            if (migrateHudson2324(as.grantedPermissions))
                OldDataMonitor.report(context, "1.301");

            return as;
        }

        protected GlobalMatrixAuthorizationStrategy create() {
            return new GlobalMatrixAuthorizationStrategy();
        }
    }
    
    public static class DescriptorImpl extends Descriptor<AuthorizationStrategy> {
        protected DescriptorImpl(Class<? extends GlobalMatrixAuthorizationStrategy> clazz) {
            super(clazz);
        }

        public DescriptorImpl() {
        }

        public String getDisplayName() {
            return Messages.GlobalMatrixAuthorizationStrategy_DisplayName();
        }

        @Override
        public AuthorizationStrategy newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            GlobalMatrixAuthorizationStrategy gmas = create();
            Map<String,Object> data = formData.getJSONObject("data");
            for(Map.Entry<String,Object> r : data.entrySet()) {
                String sid = r.getKey();
                if (!(r.getValue() instanceof JSONObject)) {
                    throw new FormException("not an object: " + formData, "data");
                }
                Map<String,Object> value = (JSONObject) r.getValue();
                for (Map.Entry<String,Object> e : value.entrySet()) {
                    if (!(e.getValue() instanceof Boolean)) {
                        throw new FormException("not an boolean: " + formData, "data");
                    }
                    if ((Boolean) e.getValue()) {
                        Permission p = Permission.fromId(e.getKey());
                        if (p == null) {
                            LOGGER.log(Level.FINE, "Silently skip unknown permission \"{0}\" for sid:\"{1}\"", new Object[]{e.getKey(), sid});
                        } else {
                            gmas.add(p, sid);
                        }
                    }
                }
            }
            return gmas;
        }

        protected GlobalMatrixAuthorizationStrategy create() {
            return new GlobalMatrixAuthorizationStrategy();
        }

        public List<PermissionGroup> getAllGroups() {
            List<PermissionGroup> groups = new ArrayList<PermissionGroup>(PermissionGroup.getAll());
            groups.remove(PermissionGroup.get(Permission.class));
            return groups;
        }

        public boolean showPermission(Permission p) {
            if (!p.getEnabled()) {
                // Permission is disabled, so don't show it
                return false;
            }

            if (ENABLE_DANGEROUS_PERMISSIONS || !DANGEROUS_PERMISSIONS.contains(p)) {
                // we allow assignment of dangerous permissions, or it's a safe permission, so show it
                return true;
            }

            // if we grant any dangerous permission, show them all
            AuthorizationStrategy strategy = Jenkins.getActiveInstance().getAuthorizationStrategy();
            if (strategy instanceof GlobalMatrixAuthorizationStrategy) {
                GlobalMatrixAuthorizationStrategy globalMatrixAuthorizationStrategy = (GlobalMatrixAuthorizationStrategy) strategy;
                return globalMatrixAuthorizationStrategy.isAnyRelevantDangerousPermissionExplicitlyGranted();
            }

            // don't show by default, i.e. when initially configuring the authorization strategy
            return false;
        }

        public FormValidation doCheckName(@QueryParameter String value ) throws IOException, ServletException {
            final Jenkins jenkins = Jenkins.getInstance();
            if (jenkins == null) { // Should never happen
                return FormValidation.error("Jenkins instance is not ready. Cannot validate the field");
            }
            return doCheckName_(value, Jenkins.getActiveInstance(), Jenkins.ADMINISTER);
        }

        public FormValidation doCheckName_(@Nonnull String value, @Nonnull AccessControlled subject, 
                @Nonnull Permission permission) throws IOException, ServletException {
            if(!subject.hasPermission(permission))  return FormValidation.ok(); // can't check

            final String v = value.substring(1,value.length()-1);
            
            final Jenkins jenkins = Jenkins.getInstance();
            if (jenkins == null) { // Should never happen
                return FormValidation.error("Jenkins instance is not ready. Cannot validate the field");
            }
            SecurityRealm sr = jenkins.getSecurityRealm();
            String ev = Functions.escape(v);

            if(v.equals("authenticated"))
                // system reserved group
                return FormValidation.respond(Kind.OK, makeImg("user.png", "Group", false) +ev);

            try {
                try {
                    sr.loadUserByUsername(v);
                    return FormValidation.respond(Kind.OK, makeImg("person.png", "User", false)+ev);
                } catch (UserMayOrMayNotExistException e) {
                    // undecidable, meaning the user may exist
                    return FormValidation.respond(Kind.OK, ev);
                } catch (UsernameNotFoundException e) {
                    // fall through next
                } catch (DataAccessException e) {
                    // fall through next
                } catch (AuthenticationException e) {
                    // other seemingly unexpected error.
                    return FormValidation.error(e,"Failed to test the validity of the user name "+v);
                }

                try {
                    sr.loadGroupByGroupname(v);
                    return FormValidation.respond(Kind.OK, makeImg("user.png", "Group", false) +ev);
                } catch (UserMayOrMayNotExistException e) {
                    // undecidable, meaning the group may exist
                    return FormValidation.respond(Kind.OK, ev);
                } catch (UsernameNotFoundException e) {
                    // fall through next
                } catch (DataAccessException e) {
                    // fall through next
                } catch (AuthenticationException e) {
                    // other seemingly unexpected error.
                    return FormValidation.error(e,"Failed to test the validity of the group name "+v);
                }

                // couldn't find it. it doesn't exist
                return FormValidation.respond(Kind.ERROR, makeImg("user-disabled.png", "User or group not found", true) + formatNonexistentUser(ev));
            } catch (Exception e) {
                // if the check fails miserably, we still want the user to be able to see the name of the user,
                // so use 'ev' as the message
                return FormValidation.error(e,ev);
            }
        }

        private String formatNonexistentUser(String username) {
            return "<span style='text-decoration: line-through; color: grey;'>" + username + "</span>";
        }

        private String makeImg(String img, String tooltip, boolean inPlugin) {
            if (inPlugin) {
                return String.format("<img src='%s/plugin/matrix-auth/images/%s' title='%s' style='margin-right:0.2em'>", Stapler.getCurrentRequest().getContextPath(), img, tooltip);
            } else {
                return String.format("<img src='%s%s/images/16x16/%s' title='%s' style='margin-right:0.2em'>", Stapler.getCurrentRequest().getContextPath(), Jenkins.RESOURCE_PATH, img, tooltip);
            }
        }
    }

    @Extension public static final class PermissionAdderImpl extends PermissionAdder {

        @Override public boolean add(AuthorizationStrategy strategy, User user, Permission perm) {
            if (strategy instanceof GlobalMatrixAuthorizationStrategy) {
                ((GlobalMatrixAuthorizationStrategy) strategy).add(perm, user.getId());
                return true;
            } else {
                return false;
            }
        }

    }

    private static final Logger LOGGER = Logger.getLogger(GlobalMatrixAuthorizationStrategy.class.getName());

    /**
     * Backwards compatibility: Enable granting dangerous permissions independently of Administer access.
     *
     * @since TODO
     */
    @SuppressFBWarnings("MS_SHOULD_BE_FINAL")
    @Restricted(NoExternalUse.class)
    public static /* allow script access */ boolean ENABLE_DANGEROUS_PERMISSIONS = Boolean.getBoolean(GlobalMatrixAuthorizationStrategy.class.getName() + ".dangerousPermissions");
}

