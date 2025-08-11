package org.jenkinsci.plugins.matrixauth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.Item;
import hudson.model.Run;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.PermissionScope;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.Test;
import org.jvnet.localizer.Localizable;
import org.jvnet.localizer.ResourceBundleHolder;

class AuthorizationContainerDescriptorTest {

    private static final Permission TEST_PERMISSION = new Permission(
            Item.PERMISSIONS,
            "Test",
            new Localizable(ResourceBundleHolder.get(AuthorizationContainerDescriptorTest.class), "Test"),
            Item.BUILD,
            PermissionScope.ITEM);

    @Test
    void testImpliedNotes() {
        { // no message on Administer
            String description =
                    new GlobalMatrixAuthorizationStrategy.DescriptorImpl().getDescription(Jenkins.ADMINISTER);
            assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionNotImpliedBy()));
            assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionImpliedBy(
                    Jenkins.PERMISSIONS.title.toString(), Jenkins.ADMINISTER.name)));
        }

        { // Run.ARTIFACTS is not implied by other permissions
            String description = new GlobalMatrixAuthorizationStrategy.DescriptorImpl().getDescription(Run.ARTIFACTS);
            assertTrue(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionNotImpliedBy()));
            assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionImpliedBy(
                    Jenkins.PERMISSIONS.title.toString(), Jenkins.ADMINISTER.name)));
        }

        {
            // Use a fake permission for the 'implied by' message addition check, since Item.CANCEL changed behavior in
            // 2.120, and there's no permission left with the same behavior.
            String description = new GlobalMatrixAuthorizationStrategy.DescriptorImpl().getDescription(TEST_PERMISSION);
            assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionNotImpliedBy()));
            assertTrue(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionImpliedBy(
                    Item.PERMISSIONS.title.toString(), Item.BUILD.name)));
        }
    }
}
