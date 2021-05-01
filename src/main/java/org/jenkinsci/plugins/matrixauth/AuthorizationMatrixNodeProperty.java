/*
 * The MIT License
 *
 * Copyright (c) 2017 Daniel Beck
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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.model.Computer;
import hudson.model.Node;
import hudson.model.User;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.PermissionScope;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import hudson.security.SidACL;
import hudson.slaves.NodeProperty;
import hudson.slaves.NodePropertyDescriptor;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import jenkins.model.NodeListener;
import net.sf.json.JSONObject;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.acls.sid.Sid;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritGlobalStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategy;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AuthorizationMatrixNodeProperty extends NodeProperty<Node> implements AuthorizationProperty {

    private final transient SidACL acl = new AclImpl();

    private final Map<Permission, Set<String>> grantedPermissions = new HashMap<>();

    private final Set<String> sids = new HashSet<>();

    /**
     * @deprecated unused, use {@link #setInheritanceStrategy(InheritanceStrategy)} instead.
     */
    @Deprecated
    @SuppressWarnings("unused")
    private transient Boolean blocksInheritance;

    private InheritanceStrategy inheritanceStrategy = new InheritGlobalStrategy();

    @Restricted(NoExternalUse.class)
    public AuthorizationMatrixNodeProperty() {
    }

    public AuthorizationMatrixNodeProperty(Map<Permission, Set<String>> grantedPermissions) {
        // do a deep copy to be safe
        for (Map.Entry<Permission,Set<String>> e : grantedPermissions.entrySet())
            this.grantedPermissions.put(e.getKey(),new HashSet<>(e.getValue()));
    }

    @Restricted(NoExternalUse.class)
    public Set<String> getGroups() {
        return new HashSet<>(sids);
    }

    /**
     * Returns all the (Permission,sid) pairs that are granted, in the multi-map form.
     *
     * @return
     *      read-only. never null.
     */
    public Map<Permission,Set<String>> getGrantedPermissions() {
        return Collections.unmodifiableMap(grantedPermissions);
    }

    @Override
    public Permission getEditingPermission() {
        return Computer.CONFIGURE;
    }

    public void setInheritanceStrategy(InheritanceStrategy inheritanceStrategy) {
        this.inheritanceStrategy = inheritanceStrategy;
    }

    public InheritanceStrategy getInheritanceStrategy() {
        return inheritanceStrategy;
    }

    /**
     * Adds to {@link #grantedPermissions}. Use of this method should be limited
     * during construction, as this object itself is considered immutable once
     * populated.
     */
    // TODO Restrict?
    public void add(Permission p, String sid) {
        grantedPermissions.computeIfAbsent(p, k -> new HashSet<>()).add(sid);
        sids.add(sid);
    }

    private final class AclImpl extends SidACL {
        @CheckForNull
        @SuppressFBWarnings(value = "NP_BOOLEAN_RETURN_NULL",
                justification = "As designed, implements a third state for the ternary logic")
        protected Boolean hasPermission(Sid sid, Permission p) {
            if (AuthorizationMatrixNodeProperty.this.hasPermission(toString(sid),p,sid instanceof PrincipalSid)) {
                return true;
            }
            return null;
        }
    }

    public SidACL getACL() {
        return acl;
    }

    /**
     * Persist {@link AuthorizationMatrixNodeProperty} as a list of IDs that
     * represent {@link AuthorizationMatrixNodeProperty#getGrantedPermissions()}.
     */
    @Restricted(NoExternalUse.class)
    @SuppressWarnings("unused")
    public static final class ConverterImpl extends AbstractAuthorizationPropertyConverter<AuthorizationMatrixNodeProperty> {
        public boolean canConvert(Class type) {
            return type == AuthorizationMatrixNodeProperty.class;
        }

        public AuthorizationMatrixNodeProperty create() {
            return new AuthorizationMatrixNodeProperty();
        }
    }

    @Extension
    public static class DescriptorImpl extends NodePropertyDescriptor implements AuthorizationPropertyDescriptor<AuthorizationMatrixNodeProperty> {

        @Restricted(NoExternalUse.class)
        @Override
        public AuthorizationMatrixNodeProperty create() {
            return new AuthorizationMatrixNodeProperty();
        }

        @Restricted(NoExternalUse.class)
        @Override
        public PermissionScope getPermissionScope() {
            return PermissionScope.COMPUTER;
        }

        @Override
        public AuthorizationMatrixNodeProperty newInstance(StaplerRequest req, @Nonnull JSONObject formData) throws FormException {
            return createNewInstance(req, formData, false);
        }

        @Override
        public boolean isApplicable(Class<? extends Node> node) {
            return isApplicable();
        }

        @Nonnull
        @Override
        public String getDisplayName() {
            return Messages.AuthorizationMatrixNodeProperty_DisplayName();
        }

        @Restricted(DoNotUse.class)
        public FormValidation doCheckName(@AncestorInPath Computer computer, @QueryParameter String value) {
            // Computer isn't a DescriptorByNameOwner before Jenkins 2.78, and then @AncestorInPath doesn't work
            return doCheckName_(value,
                    computer == null ? Jenkins.get() : computer,
                    computer == null ? Jenkins.ADMINISTER : Computer.CONFIGURE);
        }
    }


    /**
     * Ensure that the user creating a node has Read and Configure permissions
     */
    @Extension
    @Restricted(NoExternalUse.class)
    public static class NodeListenerImpl extends NodeListener {
        @Override
        protected void onCreated(@Nonnull Node node) {
            AuthorizationStrategy authorizationStrategy = Jenkins.get().getAuthorizationStrategy();
            if (authorizationStrategy instanceof ProjectMatrixAuthorizationStrategy) {
                ProjectMatrixAuthorizationStrategy strategy = (ProjectMatrixAuthorizationStrategy) authorizationStrategy;

                AuthorizationMatrixNodeProperty prop = node.getNodeProperty(AuthorizationMatrixNodeProperty.class);
                if (prop == null) {
                    prop = new AuthorizationMatrixNodeProperty();
                }

                User current = User.current();
                String sid = current == null ? "anonymous" : current.getId();

                if (!strategy.getACL(node).hasPermission2(Jenkins.getAuthentication2(), Computer.CONFIGURE)) {
                    prop.add(Computer.CONFIGURE, sid);
                }
                if (prop.getGrantedPermissions().size() > 0) {
                    try {
                        node.getNodeProperties().replace(prop);
                    } catch (IOException ex) {
                        LOGGER.log(Level.WARNING, "Failed to grant creator permissions on node " + node.getDisplayName(), ex);
                    }
                }
            }
        }
    }

    private static final Logger LOGGER = Logger.getLogger(AuthorizationMatrixNodeProperty.class.getName());
}
