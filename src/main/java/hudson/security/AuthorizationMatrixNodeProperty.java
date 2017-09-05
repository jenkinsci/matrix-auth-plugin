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
package hudson.security;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.model.Computer;
import hudson.model.Node;
import hudson.slaves.NodeProperty;
import hudson.slaves.NodePropertyDescriptor;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.acls.sid.Sid;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import javax.annotation.CheckForNull;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class AuthorizationMatrixNodeProperty extends NodeProperty<Node> implements AuthorizationProperty {

    private transient SidACL acl = new AclImpl();

    private final Map<Permission, Set<String>> grantedPermissions = new HashMap<Permission, Set<String>>();

    private Set<String> sids = new HashSet<String>();

    private boolean blocksInheritance = false;

    private AuthorizationMatrixNodeProperty() {
    }

    public AuthorizationMatrixNodeProperty(Map<Permission, Set<String>> grantedPermissions) {
        // do a deep copy to be safe
        for (Map.Entry<Permission,Set<String>> e : grantedPermissions.entrySet())
            this.grantedPermissions.put(e.getKey(),new HashSet<String>(e.getValue()));
    }

    public Set<String> getGroups() {
        return sids;
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

    /**
     * Adds to {@link #grantedPermissions}. Use of this method should be limited
     * during construction, as this object itself is considered immutable once
     * populated.
     */
    public void add(Permission p, String sid) {
        Set<String> set = grantedPermissions.get(p);
        if (set == null)
            grantedPermissions.put(p, set = new HashSet<String>());
        set.add(sid);
        sids.add(sid);
    }

    @Override
    public boolean isBlocksInheritance() {
        return blocksInheritance;
    }

    @Override
    public void setBlocksInheritance(boolean blocksInheritance) {
        this.blocksInheritance = blocksInheritance;
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
     * Persist {@link ProjectMatrixAuthorizationStrategy} as a list of IDs that
     * represent {@link ProjectMatrixAuthorizationStrategy#grantedPermissions}.
     */
    public static final class ConverterImpl extends AbstractMatrixPropertyConverter {
        public boolean canConvert(Class type) {
            return type == AuthorizationMatrixNodeProperty.class;
        }

        public AuthorizationProperty createSubject() {
            return new AuthorizationMatrixNodeProperty();
        }
    }

    @Extension
    public static class DescriptorImpl extends NodePropertyDescriptor implements AuthorizationMatrixPropertyDescriptor<AuthorizationMatrixNodeProperty> {

        @Override
        public AuthorizationMatrixNodeProperty createProperty() {
            return new AuthorizationMatrixNodeProperty();
        }

        @Override
        public PermissionScope getPermissionScope() {
            return PermissionScope.COMPUTER;
        }

        @Override
        public AuthorizationMatrixNodeProperty newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            return createNewInstance(req, formData, false);
        }

        @Override
        public boolean isApplicable(Class<? extends Node> folder) {
            return isApplicable();
        }

        @Override
        public String getDisplayName() {
            return "Authorization Matrix";
        }

        public FormValidation doCheckName(@AncestorInPath Computer computer, @QueryParameter String value) throws IOException, ServletException {
            // TODO Computer needs to become a DescriptorByNameOwner for the AncestorInPath to work
            return GlobalMatrixAuthorizationStrategy.DESCRIPTOR.doCheckName_(value,
                    computer == null ? Jenkins.getInstance() : computer,
                    computer == null ? Jenkins.ADMINISTER : Computer.CONFIGURE);
        }
    }
}
