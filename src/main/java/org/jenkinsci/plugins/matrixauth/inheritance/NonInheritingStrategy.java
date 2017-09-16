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

import hudson.Extension;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;

/**
 * Strategy that disables inheritance except for the globally defined Administer permission.
 */
public class NonInheritingStrategy extends InheritanceStrategy {

    @DataBoundConstructor
    public NonInheritingStrategy() {

    }

    @Override
    public ACL getEffectiveACL(ACL acl, AccessControlled subject) {
        final ACL rootACL = Jenkins.getInstance().getAuthorizationStrategy().getRootACL();
        return new ACL() {
            @Override
            public boolean hasPermission(@Nonnull Authentication a, @Nonnull Permission permission) {
                /*
                    I see two possible approaches here:
                    One would be to just grant every permission if the root ACL grants Administer.
                    This could result in weird situations where disabling inheritance would grant permissions like the optional
                    Run/Artifacts permission not implied by anything else.
                    The chosen, second approach checks whether the given permission is ultimately (transitively) implied by
                    Administer, and, if so, grants it if the user has Administer.
                    As this is a tree, any permission implication rooted in Administer should then be granted to administrators.
                     */
                return isUltimatelyImpliedByAdminister(permission) && rootACL.hasPermission(a, Jenkins.ADMINISTER) || acl.hasPermission(a, permission);
            }

            private boolean isUltimatelyImpliedByAdminister(Permission permission) {
                while (permission.impliedBy != null) {
                    permission = permission.impliedBy;
                }
                return permission == Jenkins.ADMINISTER;
            }
        };
    }

    @Symbol("nonInheriting")
    @Extension(ordinal = -100)
    public static class DescriptorImpl extends InheritanceStrategyDescriptor {

        @Override
        public boolean isApplicable(Class<?> clazz) {
            return true;
        }

        @Override
        @Nonnull
        public String getDisplayName() {
            return Messages.NonInheritingStrategy_DisplayName();
        }
    }
}
