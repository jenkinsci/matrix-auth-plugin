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
package org.jenkinsci.plugins.matrixauth.inheritance;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionPoint;
import hudson.model.AbstractDescribableImpl;
import hudson.model.AbstractItem;
import hudson.model.ItemGroup;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import jenkins.util.SystemProperties;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.springframework.security.core.Authentication;

public abstract class InheritanceStrategy extends AbstractDescribableImpl<InheritanceStrategy>
        implements ExtensionPoint {
    @Restricted(NoExternalUse.class)
    /* package */ static boolean isParentReadPermissionRequired() {
        return SystemProperties.getBoolean(
                hudson.security.AuthorizationMatrixProperty.class.getName() + ".checkParentPermissions", true);
    }

    @Override
    public InheritanceStrategyDescriptor getDescriptor() {
        return (InheritanceStrategyDescriptor) super.getDescriptor();
    }

    @CheckForNull
    private ACL getParentItemACL(AccessControlled accessControlled) {
        ACL parentACL = null;
        if (accessControlled instanceof AbstractItem) {
            AbstractItem item = (AbstractItem) accessControlled;
            ItemGroup<?> parent = item.getParent();
            if (parent instanceof AbstractItem) {
                parentACL = Jenkins.get().getAuthorizationStrategy().getACL((AbstractItem) parent);
            }
        }
        return parentACL;
    }

    public ACL getEffectiveACL(final ACL acl, final AccessControlled subject) {
        return ACL.lambda2((a, p) -> hasPermission(
                a,
                p,
                acl,
                getParentItemACL(subject),
                Jenkins.get().getAuthorizationStrategy().getRootACL()));
    }

    protected abstract boolean hasPermission(
            @NonNull Authentication a, @NonNull Permission permission, ACL child, @CheckForNull ACL parent, ACL root);
}
