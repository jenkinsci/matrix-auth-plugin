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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.PluginManager;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import hudson.util.FormValidation;
import hudson.Extension;
import hudson.model.User;
import net.sf.json.JSONObject;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.acls.sid.Sid;
import org.jenkinsci.plugins.matrixauth.AbstractAuthorizationContainerConverter;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainer;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainerDescriptor;
import org.jenkinsci.plugins.matrixauth.Messages;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.IOException;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

/**
 * Role-based authorization via a matrix.
 */
// TODO: think about the concurrency commitment of this class
public class GlobalMatrixAuthorizationStrategy extends AuthorizationStrategy implements AuthorizationContainer {
    private final transient SidACL acl = new AclImpl();

    /**
     * List up all permissions that are granted.
     *
     * Strings are either the granted authority or the principal,
     * which is not distinguished.
     */
    private final Map<Permission,Set<String>> grantedPermissions = new HashMap<>();

    /**
     * List of permissions considered dangerous to grant to non-admin users.
     * These are also all deprecated from Jenkins 2.222.
     */
    @Restricted(NoExternalUse.class)
    @SuppressWarnings("deprecation")
    public static final List<Permission> DANGEROUS_PERMISSIONS = Collections.unmodifiableList(Arrays.asList(
            Jenkins.RUN_SCRIPTS,
            PluginManager.CONFIGURE_UPDATECENTER,
            PluginManager.UPLOAD_PLUGINS
    ));

    private final Set<String> sids = new HashSet<>();

    /**
     * Adds to {@link #grantedPermissions}.
     * Use of this method should be limited during construction,
     * as this object itself is considered immutable once populated.
     */
    public void add(Permission p, String sid) {
        if (p==null)
            throw new IllegalArgumentException("Permission can not be null for sid:" + sid);

        LOGGER.log(Level.FINE, "Grant permission \"{0}\" to \"{1}\")", new Object[]{p, sid});
        grantedPermissions.computeIfAbsent(p, k -> new HashSet<>()).add(sid);
        sids.add(sid);
    }

    public Map<Permission, Set<String>> getGrantedPermissions() {
        return Collections.unmodifiableMap(grantedPermissions);
    }

    @Override
    public Permission getEditingPermission() {
        return Jenkins.ADMINISTER;
    }

    @Override
    @Nonnull
    public ACL getRootACL() {
        return acl;
    }

    @Override
    @Nonnull
    public Set<String> getGroups() {
        final TreeSet<String> sids = new TreeSet<>(new IdStrategyComparator());
        sids.addAll(this.sids);
        return sids;
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
    @Restricted(NoExternalUse.class)
    public static class ConverterImpl extends AbstractAuthorizationContainerConverter<GlobalMatrixAuthorizationStrategy> {
        public boolean canConvert(Class type) {
            return type == GlobalMatrixAuthorizationStrategy.class;
        }

        @Override
        public GlobalMatrixAuthorizationStrategy create() {
            return new GlobalMatrixAuthorizationStrategy();
        }
    }
    
    public static class DescriptorImpl extends Descriptor<AuthorizationStrategy> implements AuthorizationContainerDescriptor<GlobalMatrixAuthorizationStrategy> {

        public DescriptorImpl() {
            // make this constructor available for instantiation for ProjectMatrixAuthorizationStrategy
            // public for role-strategy plugin
        }

        @Override
        public PermissionScope getPermissionScope() {
            return PermissionScope.JENKINS;
        }

        @Nonnull
        public String getDisplayName() {
            return Messages.GlobalMatrixAuthorizationStrategy_DisplayName();
        }

        @Override
        public AuthorizationStrategy newInstance(StaplerRequest req, @Nonnull JSONObject formData) throws FormException {
            // TODO Is there a way to pull this up into AuthorizationContainerDescriptor and share code with AuthorizationPropertyDescriptor?
            GlobalMatrixAuthorizationStrategy globalMatrixAuthorizationStrategy = create();
            Map<String,Object> data = formData.getJSONObject("data");

            boolean adminAdded = false;

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
                            if (p == Jenkins.ADMINISTER) {
                                adminAdded = true;
                            }
                            globalMatrixAuthorizationStrategy.add(p, sid);
                        }
                    }
                }
            }

            if (!adminAdded) {
                User current = User.current();
                String id;
                if (current == null) {
                    id = "anonymous";
                } else {
                    id = current.getId();
                }
                globalMatrixAuthorizationStrategy.add(Jenkins.ADMINISTER, id);
            }

            return globalMatrixAuthorizationStrategy;
        }

        protected GlobalMatrixAuthorizationStrategy create() {
            return new GlobalMatrixAuthorizationStrategy();
        }

        @Restricted(NoExternalUse.class)
        public FormValidation doCheckName(@QueryParameter String value ) {
            return doCheckName_(value, Jenkins.get(), Jenkins.ADMINISTER);
        }

    }

    @Restricted(DoNotUse.class)
    @Extension public static final class PermissionAdderImpl extends PermissionAdder {

        @Override public boolean add(AuthorizationStrategy strategy, User user, Permission perm) {
            if (strategy instanceof GlobalMatrixAuthorizationStrategy) {
                ((GlobalMatrixAuthorizationStrategy) strategy).add(perm, user.getId());
                try {
                    Jenkins.get().save();
                } catch (IOException ioe) {
                    LOGGER.log(Level.WARNING, "Failed to save Jenkins after adding permission for user: " + user.getId(), ioe);
                }
                return true;
            } else {
                return false;
            }
        }

    }

    private static final Logger LOGGER = Logger.getLogger(GlobalMatrixAuthorizationStrategy.class.getName());
}

