package org.jenkinsci.plugins.matrixauth;

import hudson.model.Item;
import hudson.model.Run;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.PermissionScope;
import jenkins.model.Jenkins;
import org.junit.Assert;
import org.junit.Test;
import org.jvnet.localizer.Localizable;
import org.jvnet.localizer.ResourceBundleHolder;

public class AuthorizationContainerDescriptorTest {

    private final Permission TEST_PERMISSION = new Permission(Item.PERMISSIONS, "Test", new Localizable(ResourceBundleHolder.get(AuthorizationContainerDescriptorTest.class), "Test"), Item.BUILD, PermissionScope.ITEM);

    @Test
    public void testImpliedNotes() {
        { // no message on Administer
            String description = new GlobalMatrixAuthorizationStrategy.DescriptorImpl().getDescription(Jenkins.ADMINISTER);
            Assert.assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionNotImpliedBy()));
            Assert.assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionImpliedBy(Jenkins.PERMISSIONS.title.toString(), Jenkins.ADMINISTER.name)));
        }

        { // Run.ARTIFACTS is not implied by other permissions
            String description = new GlobalMatrixAuthorizationStrategy.DescriptorImpl().getDescription(Run.ARTIFACTS);
            Assert.assertTrue(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionNotImpliedBy()));
            Assert.assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionImpliedBy(Jenkins.PERMISSIONS.title.toString(), Jenkins.ADMINISTER.name)));
        }

        {
            // Use a fake permission for the 'implied by' message addition check, since Item.CANCEL changed behavior in 2.120, and there's no permission left with the same behavior.
            String description = new GlobalMatrixAuthorizationStrategy.DescriptorImpl().getDescription(TEST_PERMISSION);
            Assert.assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionNotImpliedBy()));
            Assert.assertTrue(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionImpliedBy(Item.PERMISSIONS.title.toString(), Item.BUILD.name)));
        }
    }
}
