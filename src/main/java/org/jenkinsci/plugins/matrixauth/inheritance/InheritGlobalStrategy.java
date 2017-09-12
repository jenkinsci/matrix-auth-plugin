package org.jenkinsci.plugins.matrixauth.inheritance;

import hudson.Extension;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;

/**
 * Strategy that inherits only the global ACL -- parent, grandparent, etc. ACLs are not inherited.
 */
public class InheritGlobalStrategy extends InheritanceStrategy {

    @DataBoundConstructor
    public InheritGlobalStrategy() {

    }
    
    @Override
    public ACL getEffectiveACL(ACL acl, AccessControlled subject) {
        return ProjectMatrixAuthorizationStrategy.inheritingACL(Jenkins.getInstance().getAuthorizationStrategy().getRootACL(), acl);
    }

    @Extension
    public static class DescriptorImpl extends InheritanceStrategyDescriptor {

        @Override
        public boolean isApplicable(Class<?> clazz) {
            return true;
        }

        @Override
        @Nonnull
        public String getDisplayName() {
            return "Inherit globally defined permissions"; // TODO i18n
        }
    }
}
