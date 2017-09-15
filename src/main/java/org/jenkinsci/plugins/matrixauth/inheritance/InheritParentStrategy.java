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
import hudson.model.AbstractItem;
import hudson.model.ItemGroup;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;

/**
 * Strategy that inherits the ACL from the parent.
 *
 * The paren't inheritance strategy in turn determines whether this receives permissions from grandparents etc. up to root.
 */
public class InheritParentStrategy extends InheritanceStrategy {

    @DataBoundConstructor
    public InheritParentStrategy() {

    }

    @Override
    public ACL getEffectiveACL(ACL acl, AccessControlled subject) {
        if (subject instanceof AbstractItem) {
            AbstractItem item = (AbstractItem) subject;
            ItemGroup parent = item.getParent();
            final ACL parentACL;
            if (parent instanceof AbstractItem) {
                parentACL = Jenkins.getInstance().getAuthorizationStrategy().getACL((AbstractItem) parent);
            } else {
                parentACL = Jenkins.getInstance().getAuthorizationStrategy().getRootACL();
            }
            return ProjectMatrixAuthorizationStrategy.inheritingACL(parentACL, acl);
        } else {
            throw new IllegalArgumentException("Expected subject to be AbstractItem, but got " + subject);
        }
    }

    @Extension(ordinal = 100)
    public static class DescriptorImpl extends InheritanceStrategyDescriptor {

        @Override
        public boolean isApplicable(Class<?> clazz) {
            return AbstractItem.class.isAssignableFrom(clazz);
        }

        @Override
        @Nonnull
        public String getDisplayName() {
            return Messages.InheritParentStrategy_DisplayName();
        }
    }
}
