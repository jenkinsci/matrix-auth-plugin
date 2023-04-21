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
import hudson.Extension;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.security.Permission;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.security.core.Authentication;

/**
 * Strategy that inherits only the global ACL -- parent, grandparent, etc. ACLs are not inherited.
 */
public class InheritGlobalStrategy extends InheritanceStrategy {

    @DataBoundConstructor
    public InheritGlobalStrategy() {}

    @Override
    protected boolean hasPermission(
            @NonNull Authentication a, @NonNull Permission permission, ACL child, @CheckForNull ACL parent, ACL root) {
        if (a.equals(ACL.SYSTEM2)) {
            return true;
        }
        if (isParentReadPermissionRequired()
                && parent != null
                && (Item.READ.equals(permission) || Item.DISCOVER.equals(permission))) {
            /*
             * We need special handling for Read/Discover permissions to prevent SECURITY-2180:
             * Item/Read is expected to only be effective if it is granted on every ancestor, similar to how permissions
             * granted while lacking Overall/Read are pointless.
             * If and only if we check for Item/Read or Item/Discover, do not fall back to the permission granted globally.
             * No need to check #isUltimatelyImpliedByAdminister like NonInheritingStrategy does, we know it to be true for these permissions.
             *
             * This is a nested element.
             * We need to ensure that all of the following are true:
             * - The permission is granted in the parent
             * - The permission is granted globally or explicitly on this element (the child)
             */
            final boolean grantedViaChild = child.hasPermission2(a, permission);
            final boolean grantedGlobally = root.hasPermission2(a, permission);
            final boolean grantedInParent = parent.hasPermission2(a, permission);
            return (grantedViaChild || grantedGlobally) && grantedInParent;
        }
        return child.hasPermission2(a, permission) || root.hasPermission2(a, permission);
    }

    @Symbol("inheritingGlobal")
    @Extension
    public static class DescriptorImpl extends InheritanceStrategyDescriptor {

        @Override
        public boolean isApplicable(Class<?> clazz) {
            return true;
        }

        @Override
        @NonNull
        public String getDisplayName() {
            return Messages.InheritGlobalStrategy_DisplayName();
        }
    }
}
