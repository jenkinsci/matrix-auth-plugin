package org.jenkinsci.plugins.matrixauth;

import hudson.model.Item;
import hudson.model.Run;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import jenkins.model.Jenkins;
import org.junit.Assert;
import org.junit.Test;

public class AuthorizationContainerDescriptorTest {
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

        { // Item.CANCEL is implied by Item.BUILD (at least up to core 2.111)
            String description = new GlobalMatrixAuthorizationStrategy.DescriptorImpl().getDescription(Item.CANCEL);
            Assert.assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionNotImpliedBy()));
            Assert.assertTrue(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionImpliedBy(Item.PERMISSIONS.title.toString(), Item.BUILD.name)));
        }
    }
}
