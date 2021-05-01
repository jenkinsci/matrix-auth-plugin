/*
 * The MIT License
 * 
 * Copyright (c) 2004-2010, Sun Microsystems, Inc., Kohsuke Kawaguchi, Yahoo! Inc., Peter Hayes, Tom Huybrechts
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
import hudson.Extension;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.JobPropertyDescriptor;
import hudson.model.User;
import hudson.model.listeners.ItemListener;
import hudson.util.FormValidation;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;

import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.acls.sid.Sid;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.matrixauth.AbstractAuthorizationPropertyConverter;
import org.jenkinsci.plugins.matrixauth.AuthorizationPropertyDescriptor;
import org.jenkinsci.plugins.matrixauth.AuthorizationProperty;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategy;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.verb.GET;

/**
 * {@link JobProperty} to associate ACL for each project.
 *
 * <p>
 * Once created (and initialized), this object becomes immutable.
 */
// TODO attempt to make this OptionalJobProperty
public class AuthorizationMatrixProperty extends JobProperty<Job<?, ?>> implements AuthorizationProperty {

    private final transient SidACL acl = new AclImpl();

    /**
     * List up all permissions that are granted.
     * <p>
     * Strings are either the granted authority or the principal, which is not
     * distinguished.
     */
    private final Map<Permission, Set<String>> grantedPermissions = new HashMap<>();

    private final Set<String> sids = new HashSet<>();

    /**
     * @deprecated unused, use {@link #setInheritanceStrategy(InheritanceStrategy)} instead.
     */
    @Deprecated
    @SuppressWarnings("unused")
    private transient Boolean blocksInheritance;

    private InheritanceStrategy inheritanceStrategy = new InheritParentStrategy();

    private AuthorizationMatrixProperty() {
    }

    public AuthorizationMatrixProperty(Map<Permission, Set<String>> grantedPermissions) {
        // do a deep copy to be safe
        for (Entry<Permission, Set<String>> e : grantedPermissions.entrySet())
            this.grantedPermissions.put(e.getKey(), new HashSet<>(e.getValue()));
    }

    @DataBoundConstructor
    public AuthorizationMatrixProperty(List<String> permissions) {
        for (String str : permissions) {
            if (str != null) {
                this.add(str);
            }
        }
    }

    public List<String> getPermissions() {
        List<String> permissions = new ArrayList<>();

        SortedMap<Permission, Set<String>> map = new TreeMap<>(Comparator.comparing(Permission::getId));
        map.putAll(this.grantedPermissions);
        for (Map.Entry<Permission, Set<String>> entry : map.entrySet()) {
            String permission = entry.getKey().getId();
            for (String sid : new TreeSet<>(entry.getValue())) {
                permissions.add(permission + ":" + sid);
            }
        }
        return permissions;
    }

    public Set<String> getGroups() {
        return new HashSet<>(sids);
    }

    /**
     * Returns all the (Permission,sid) pairs that are granted, in the multi-map form.
     *
     * @return read-only. never null.
     */
    public Map<Permission, Set<String>> getGrantedPermissions() {
        return Collections.unmodifiableMap(grantedPermissions);
    }

    @Override
    public Permission getEditingPermission() {
        return Item.CONFIGURE;
    }

    /**
     * Adds to {@link #grantedPermissions}. Use of this method should be limited
     * during construction, as this object itself is considered immutable once
     * populated.
     */
    public void add(Permission p, String sid) {
        grantedPermissions.computeIfAbsent(p, k -> new HashSet<>()).add(sid);
        sids.add(sid);
    }

    @Extension
    @Symbol("authorizationMatrix")
    public static class DescriptorImpl extends JobPropertyDescriptor implements AuthorizationPropertyDescriptor<AuthorizationMatrixProperty> {

        @Override
        public AuthorizationMatrixProperty create() {
            return new AuthorizationMatrixProperty();
        }

        @Override
        public PermissionScope getPermissionScope() {
            return PermissionScope.ITEM;
        }

        @Override
        public JobProperty<?> newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            return createNewInstance(req, formData, true);
        }

        @Override
        public boolean isApplicable(Class<? extends Job> jobType) {
            return isApplicable();
        }

        @GET
        public FormValidation doCheckName(@AncestorInPath Job<?, ?> project, @QueryParameter String value) {
            return doCheckName_(value, project, Item.CONFIGURE);
        }
    }

    private final class AclImpl extends SidACL {
        @CheckForNull
        @SuppressFBWarnings(value = "NP_BOOLEAN_RETURN_NULL",
                justification = "As designed, implements a third state for the ternary logic")
        protected Boolean hasPermission(Sid sid, Permission p) {
            if (AuthorizationMatrixProperty.this.hasPermission(toString(sid), p, sid instanceof PrincipalSid)) {
                return true;
            }
            return null;
        }
    }

    public SidACL getACL() {
        return acl;
    }

    @DataBoundSetter
    public void setInheritanceStrategy(InheritanceStrategy inheritanceStrategy) {
        this.inheritanceStrategy = inheritanceStrategy;
    }

    public InheritanceStrategy getInheritanceStrategy() {
        return inheritanceStrategy;
    }

    /**
     * Persist {@link AuthorizationMatrixProperty} as a list of IDs that
     * represent {@link AuthorizationMatrixProperty#getGrantedPermissions()}.
     */
    @Restricted(DoNotUse.class)
    @SuppressWarnings("unused")
    public static final class ConverterImpl extends AbstractAuthorizationPropertyConverter<AuthorizationMatrixProperty> {
        public boolean canConvert(Class type) {
            return type == AuthorizationMatrixProperty.class;
        }

        public AuthorizationMatrixProperty create() {
            return new AuthorizationMatrixProperty();
        }
    }

    /**
     * Ensure that the user creating a job has Read and Configure permissions
     */
    @Extension
    @Restricted(NoExternalUse.class)
    public static class ItemListenerImpl extends ItemListener {
        @Override
        public void onCreated(Item item) {
            AuthorizationStrategy authorizationStrategy = Jenkins.get().getAuthorizationStrategy();
            if (authorizationStrategy instanceof ProjectMatrixAuthorizationStrategy) {
                ProjectMatrixAuthorizationStrategy strategy = (ProjectMatrixAuthorizationStrategy) authorizationStrategy;

                if (item instanceof Job) {
                    Job<?, ?> job = (Job<?, ?>) item;
                    AuthorizationMatrixProperty prop = job.getProperty(AuthorizationMatrixProperty.class);
                    boolean propIsNew = prop == null;
                    if (propIsNew) {
                        prop = new AuthorizationMatrixProperty();
                    }

                    User current = User.current();
                    String sid = current == null ? "anonymous" : current.getId();

                    if (!strategy.getACL(job).hasPermission2(Jenkins.getAuthentication2(), Item.READ)) {
                        prop.add(Item.READ, sid);
                    }
                    if (!strategy.getACL(job).hasPermission2(Jenkins.getAuthentication2(), Item.CONFIGURE)) {
                        prop.add(Item.CONFIGURE, sid);
                    }
                    if (prop.getGrantedPermissions().size() > 0) {
                        try {
                            if (propIsNew) {
                                job.addProperty(prop);
                            } else {
                                job.save();
                            }
                        } catch (IOException ex) {
                            LOGGER.log(Level.WARNING, "Failed to grant creator permissions on job " + item.getFullName(), ex);
                        }
                    }
                }
            }
        }
    }

    private static final Logger LOGGER = Logger.getLogger(AuthorizationMatrixProperty.class.getName());
}
