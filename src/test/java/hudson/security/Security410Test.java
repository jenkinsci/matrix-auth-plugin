package hudson.security;

import hudson.PluginManager;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class Security410Test {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Issue("SECURITY-410")
    @Test
    public void dangerousPermissions1() {
        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        assertFalse(((GlobalMatrixAuthorizationStrategy.DescriptorImpl) as.getDescriptor()).showPermission(Jenkins.RUN_SCRIPTS));
        assertFalse(((GlobalMatrixAuthorizationStrategy.DescriptorImpl) as.getDescriptor()).showPermission(PluginManager.CONFIGURE_UPDATECENTER));
        assertFalse(((GlobalMatrixAuthorizationStrategy.DescriptorImpl) as.getDescriptor()).showPermission(PluginManager.UPLOAD_PLUGINS));

        try {
            GlobalMatrixAuthorizationStrategy.ENABLE_DANGEROUS_PERMISSIONS = true;
            assertTrue(((GlobalMatrixAuthorizationStrategy.DescriptorImpl) as.getDescriptor()).showPermission(Jenkins.RUN_SCRIPTS));
            assertTrue(((GlobalMatrixAuthorizationStrategy.DescriptorImpl) as.getDescriptor()).showPermission(PluginManager.CONFIGURE_UPDATECENTER));
            assertTrue(((GlobalMatrixAuthorizationStrategy.DescriptorImpl) as.getDescriptor()).showPermission(PluginManager.UPLOAD_PLUGINS));
        } finally {
            GlobalMatrixAuthorizationStrategy.ENABLE_DANGEROUS_PERMISSIONS = false;
        }
    }

    @LocalData
    @Test
    public void testUpgradeWithRelevantDangerousPermissions() {
        assertTrue(j.jenkins.getAuthorizationStrategy() instanceof GlobalMatrixAuthorizationStrategy);

        GlobalMatrixAuthorizationStrategy strategy = (GlobalMatrixAuthorizationStrategy) j.jenkins.getAuthorizationStrategy();
        assertEquals("two known users", 2, strategy.getAllSIDs().size());
        assertTrue("active monitor", j.jenkins.getAdministrativeMonitor(DangerousMatrixPermissionsAdministrativeMonitor.class.getName()).isActivated());
        assertTrue("show permissions", strategy.isAnyRelevantDangerousPermissionExplicitlyGranted());
        assertFalse("alice is admin so no relevant dangerous permissions", strategy.isAnyRelevantDangerousPermissionExplicitlyGranted("alice"));
        assertTrue("bob is not admin but has dangerous permission", strategy.isAnyRelevantDangerousPermissionExplicitlyGranted("bob"));
        assertTrue("show dangerous permissions in config", ((GlobalMatrixAuthorizationStrategy.DescriptorImpl)strategy.getDescriptor()).showPermission(Jenkins.RUN_SCRIPTS));
        assertFalse("do not grant scripts permission to bob", strategy.hasPermission("bob", Jenkins.RUN_SCRIPTS));
        assertTrue("grant scripts permission to alice", strategy.hasPermission("alice", Jenkins.RUN_SCRIPTS));

        try {
            GlobalMatrixAuthorizationStrategy.ENABLE_DANGEROUS_PERMISSIONS = true;

            assertTrue("show dangerous permissions in config", ((GlobalMatrixAuthorizationStrategy.DescriptorImpl)strategy.getDescriptor()).showPermission(Jenkins.RUN_SCRIPTS));
            assertTrue("grant permission to bob", strategy.hasPermission("bob", Jenkins.RUN_SCRIPTS));
            assertFalse("disabled admin monitor", j.jenkins.getAdministrativeMonitor(DangerousMatrixPermissionsAdministrativeMonitor.class.getName()).isActivated());
        } finally {
            GlobalMatrixAuthorizationStrategy.ENABLE_DANGEROUS_PERMISSIONS = false;
        }
    }

    @LocalData
    @Test
    public void testUpgradeWithNoRelevantDangerousPermissions() {
        assertTrue(j.jenkins.getAuthorizationStrategy() instanceof GlobalMatrixAuthorizationStrategy);

        GlobalMatrixAuthorizationStrategy strategy = (GlobalMatrixAuthorizationStrategy) j.jenkins.getAuthorizationStrategy();
        assertEquals("two known users", 2, strategy.getAllSIDs().size());
        assertFalse("not active monitor", j.jenkins.getAdministrativeMonitor(DangerousMatrixPermissionsAdministrativeMonitor.class.getName()).isActivated());
        assertFalse("do not show permissions", strategy.isAnyRelevantDangerousPermissionExplicitlyGranted());
        assertFalse("alice has no relevant dangerous permissions", strategy.isAnyRelevantDangerousPermissionExplicitlyGranted("alice"));
        assertFalse("bob has no relevant dangerous permissions", strategy.isAnyRelevantDangerousPermissionExplicitlyGranted("bob"));
        assertFalse("show dangerous permissions in config", ((GlobalMatrixAuthorizationStrategy.DescriptorImpl)strategy.getDescriptor()).showPermission(Jenkins.RUN_SCRIPTS));
    }
}
