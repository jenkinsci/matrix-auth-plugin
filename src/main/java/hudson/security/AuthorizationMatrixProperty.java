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

import edu.umd.cs.findbugs.annotations.CheckForNull;
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
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.acls.sid.Sid;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.matrixauth.AbstractAuthorizationPropertyConverter;
import org.jenkinsci.plugins.matrixauth.AmbiguityMonitor;
import org.jenkinsci.plugins.matrixauth.AuthorizationProperty;
import org.jenkinsci.plugins.matrixauth.AuthorizationPropertyDescriptor;
import org.jenkinsci.plugins.matrixauth.AuthorizationType;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategy;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.accmod.restrictions.NoExternalUse;
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
    private final Map<Permission, Set<PermissionEntry>> grantedPermissions = new HashMap<>();

    private final Set<String> groupSids = Collections.synchronizedSet(new HashSet<>());

    /**
     * @deprecated unused, use {@link #setInheritanceStrategy(InheritanceStrategy)} instead.
     */
    @Deprecated
    @SuppressWarnings("unused")
    private transient Boolean blocksInheritance;

    private InheritanceStrategy inheritanceStrategy = new InheritParentStrategy();

    private AuthorizationMatrixProperty() {}

    /**
     * @since 3.0
     */
    // TODO(3.0) is this even needed? Why is the no-arg constructor private?
    public AuthorizationMatrixProperty(
            Map<Permission, Set<PermissionEntry>> grantedPermissions, InheritanceStrategy inheritanceStrategy) {
        this.inheritanceStrategy = inheritanceStrategy;
        grantedPermissions.forEach((key, value) -> {
            this.grantedPermissions.put(key, new HashSet<>(value));
            value.forEach(entry -> {
                if (entry.getType() != AuthorizationType.USER) {
                    this.recordGroup(entry.getSid());
                }
            });
        });
    }

    /**
     * @deprecated Use {@link #AuthorizationMatrixProperty(Map, InheritanceStrategy)} instead.
     */
    @Deprecated
    public AuthorizationMatrixProperty(Map<Permission, Set<String>> grantedPermissions) {
        for (Map.Entry<Permission, ? extends Set<String>> e : grantedPermissions.entrySet()) {
            this.grantedPermissions.put(
                    e.getKey(),
                    e.getValue().stream()
                            .map(sid -> new PermissionEntry(AuthorizationType.EITHER, sid))
                            .collect(Collectors.toSet()));
        }
    }

    @DataBoundConstructor
    public AuthorizationMatrixProperty(List<String> permissions) {
        for (String str : permissions) {
            if (str != null) {
                this.add(str);
            }
        }
    }

    /**
     * Getter corresponding to databound contructor for Pipeline snippetizer.
     */
    public List<String> getPermissions() {
        List<String> permissions = new ArrayList<>();

        SortedMap<Permission, Set<PermissionEntry>> map = new TreeMap<>(Comparator.comparing(Permission::getId));
        map.putAll(this.grantedPermissions);
        for (Map.Entry<Permission, Set<PermissionEntry>> entry : map.entrySet()) {
            String permission = entry.getKey().getId();
            final TreeSet<PermissionEntry> permissionEntries = new TreeSet<>(new PermissionEntryComparator());
            permissionEntries.addAll(entry.getValue());
            for (PermissionEntry e : permissionEntries) {
                permissions.add(e.getType().toPrefix() + permission + ":" + e.getSid());
            }
        }
        return permissions;
    }

    @Override
    public Set<String> getGroups() {
        return groupSids;
    }

    @Override
    public void recordGroup(String sid) {
        this.groupSids.add(sid);
    }

    @Override
    public Map<Permission, Set<PermissionEntry>> getGrantedPermissionEntries() {
        return grantedPermissions;
    }

    @Override
    public Permission getEditingPermission() {
        return Item.CONFIGURE;
    }

    @Extension
    @Symbol("authorizationMatrix")
    public static class DescriptorImpl extends JobPropertyDescriptor
            implements AuthorizationPropertyDescriptor<AuthorizationMatrixProperty> {

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
        @SuppressFBWarnings(
                value = "NP_BOOLEAN_RETURN_NULL",
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

    @Override
    protected void setOwner(Job<?, ?> owner) {
        super.setOwner(owner);
        AmbiguityMonitor.JobContributor.update(owner);
    }

    /**
     * Persist {@link AuthorizationMatrixProperty} as a list of IDs that
     * represent {@link AuthorizationMatrixProperty#getGrantedPermissionEntries()}.
     */
    @Restricted(DoNotUse.class)
    @SuppressWarnings("unused")
    public static final class ConverterImpl
            extends AbstractAuthorizationPropertyConverter<AuthorizationMatrixProperty> {
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
                ProjectMatrixAuthorizationStrategy strategy =
                        (ProjectMatrixAuthorizationStrategy) authorizationStrategy;

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
                        prop.add(Item.READ, new PermissionEntry(AuthorizationType.USER, sid));
                    }
                    if (!strategy.getACL(job).hasPermission2(Jenkins.getAuthentication2(), Item.CONFIGURE)) {
                        prop.add(Item.CONFIGURE, new PermissionEntry(AuthorizationType.USER, sid));
                    }
                    if (prop.getGrantedPermissionEntries().size() > 0) {
                        try {
                            if (propIsNew) {
                                job.addProperty(prop);
                            } else {
                                job.save();
                            }
                        } catch (IOException ex) {
                            LOGGER.log(
                                    Level.WARNING,
                                    "Failed to grant creator permissions on job " + item.getFullName(),
                                    ex);
                        }
                    }
                }
            }
        }
    }

    private static final Logger LOGGER = Logger.getLogger(AuthorizationMatrixProperty.class.getName());
}
