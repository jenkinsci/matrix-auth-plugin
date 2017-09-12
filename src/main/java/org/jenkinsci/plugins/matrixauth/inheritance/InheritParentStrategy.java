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
            return "Inherit permissions from parent ACL"; // TODO i18n
        }
    }
}
