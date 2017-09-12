package org.jenkinsci.plugins.matrixauth.inheritance;

import hudson.Extension;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
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
                if (isUltimatelyImpliedByAdminister(permission) && rootACL.hasPermission(a, Jenkins.ADMINISTER)) {
                    /*
                    I see two possible approaches here:
                    One would be to just grant every permission if the root ACL grants Administer.
                    This could result in weird situations where disabling inheritance would grant permissions like the optional
                    Run/Artifacts permission not implied by anything else.
                    The chosen, second approach checks whether the given permission is ultimately (transitively) implied by
                    Administer, and, if so, grants it if the user has Administer.
                    As this is a tree, any permission implication rooted in Administer should then be granted to administrators.
                     */
                    return true;
                }
                return acl.hasPermission(a, permission);
            }

            private boolean isUltimatelyImpliedByAdminister(Permission permission) {
                while (permission.impliedBy != null) {
                    permission = permission.impliedBy;
                }
                return permission == Jenkins.ADMINISTER;
            }
        };
    }
    
    @Extension(ordinal = -100)
    public static class DescriptorImpl extends InheritanceStrategyDescriptor {

        @Override
        public boolean isApplicable(Class<?> clazz) {
            return true;
        }

        @Override
        @Nonnull
        public String getDisplayName() {
            return "Do not inherit permission grants from other ACLs"; // TODO i18n
        }
    }
}
