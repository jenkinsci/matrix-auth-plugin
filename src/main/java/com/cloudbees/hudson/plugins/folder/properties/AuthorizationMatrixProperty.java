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
package com.cloudbees.hudson.plugins.folder.properties;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.AbstractFolderProperty;
import com.cloudbees.hudson.plugins.folder.AbstractFolderPropertyDescriptor;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.model.AbstractItem;
import hudson.model.Item;
import hudson.model.User;
import hudson.model.listeners.ItemListener;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.PermissionScope;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import hudson.security.SidACL;
import hudson.util.FormValidation;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.acls.sid.Sid;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.matrixauth.AbstractAuthorizationPropertyConverter;
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
 * Holds ACL for {@link ProjectMatrixAuthorizationStrategy}.
 */
public class AuthorizationMatrixProperty extends AbstractFolderProperty<AbstractFolder<?>>
        implements AuthorizationProperty {

    private final transient SidACL acl = new AclImpl();

    /**
     * List up all permissions that are granted.
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

    protected AuthorizationMatrixProperty() {}

    // TODO(3.0) How is this used?
    @Deprecated
    public AuthorizationMatrixProperty(Map<Permission, ? extends Set<String>> grantedPermissions) {
        for (Map.Entry<Permission, ? extends Set<String>> e : grantedPermissions.entrySet()) {
            this.grantedPermissions.put(
                    e.getKey(),
                    e.getValue().stream()
                            .map(sid -> new PermissionEntry(AuthorizationType.EITHER, sid))
                            .collect(Collectors.toSet()));
        }
    }

    @DataBoundConstructor // JENKINS-49199: Used for job-dsl
    @Restricted(NoExternalUse.class)
    public AuthorizationMatrixProperty(List<String> permissions) {
        for (String permission : permissions) {
            add(permission);
        }
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

    @Override
    protected void setOwner(@NonNull AbstractFolder<?> owner) {
        super.setOwner(owner);
        FolderContributor.record(owner);
    }

    @Extension(optional = true)
    @Symbol("authorizationMatrix")
    public static class DescriptorImpl extends AbstractFolderPropertyDescriptor
            implements AuthorizationPropertyDescriptor<AuthorizationMatrixProperty> {

        @Override
        public AuthorizationMatrixProperty create() {
            return new AuthorizationMatrixProperty();
        }

        @Override
        public PermissionScope getPermissionScope() {
            return PermissionScope.ITEM_GROUP;
        }

        @Override
        public AuthorizationMatrixProperty newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            return createNewInstance(req, formData, true);
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractFolder> folder) {
            return isApplicable();
        }

        @GET
        public FormValidation doCheckName(@AncestorInPath AbstractFolder<?> folder, @QueryParameter String value) {
            return doCheckName_(value, folder, Item.CONFIGURE);
        }
    }

    private final class AclImpl extends SidACL {
        @SuppressFBWarnings(value = "NP_BOOLEAN_RETURN_NULL", justification = "Because that is the way this SPI works")
        protected Boolean hasPermission(Sid sid, Permission p) {
            if (AuthorizationMatrixProperty.this.hasPermission(toString(sid), p, sid instanceof PrincipalSid))
                return true;
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
    public static final class ConverterImpl
            extends AbstractAuthorizationPropertyConverter<AuthorizationMatrixProperty> {
        public boolean canConvert(Class type) {
            return type == AuthorizationMatrixProperty.class;
        }

        @Override
        public AuthorizationMatrixProperty create() {
            return new AuthorizationMatrixProperty();
        }
    }

    /**
     * Ensure that the user creating a folder has Read and Configure permissions
     */
    @Extension(optional = true)
    @Restricted(NoExternalUse.class)
    public static class ItemListenerImpl extends ItemListener {
        @Override
        public void onCreated(Item item) {
            AuthorizationStrategy authorizationStrategy = Jenkins.get().getAuthorizationStrategy();
            if (authorizationStrategy instanceof ProjectMatrixAuthorizationStrategy) {
                ProjectMatrixAuthorizationStrategy strategy =
                        (ProjectMatrixAuthorizationStrategy) authorizationStrategy;

                if (item instanceof AbstractFolder) {
                    AbstractFolder<?> folder = (AbstractFolder<?>) item;
                    AuthorizationMatrixProperty prop = folder.getProperties().get(AuthorizationMatrixProperty.class);
                    boolean propIsNew = prop == null;
                    if (propIsNew) {
                        prop = new AuthorizationMatrixProperty();
                    }

                    User current = User.current();
                    String sid = current == null ? "anonymous" : current.getId();

                    if (!strategy.getACL((AbstractItem) folder)
                            .hasPermission2(Jenkins.getAuthentication2(), Item.READ)) {
                        prop.add(Item.READ, PermissionEntry.user(sid));
                    }
                    if (!strategy.getACL((AbstractItem) folder)
                            .hasPermission2(Jenkins.getAuthentication2(), Item.CONFIGURE)) {
                        prop.add(Item.CONFIGURE, PermissionEntry.user(sid));
                    }
                    if (prop.getGrantedPermissionEntries().size() > 0) {
                        try {
                            if (propIsNew) {
                                folder.addProperty(prop);
                            } else {
                                folder.save();
                            }
                        } catch (IOException ex) {
                            LOGGER.log(
                                    Level.WARNING,
                                    "Failed to grant creator permissions on folder " + item.getFullName(),
                                    ex);
                        }
                    }
                }
            }
        }
    }

    private static final Logger LOGGER = Logger.getLogger(AuthorizationMatrixProperty.class.getName());
}
