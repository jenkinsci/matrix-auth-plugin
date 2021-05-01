package hudson.security;

import hudson.PluginManager;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.assertFalse;

public class Security410Test {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Issue("SECURITY-410")
    @Test
    @SuppressWarnings("deprecation")
    public void dangerousPermissions1() {
        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        assertFalse(((GlobalMatrixAuthorizationStrategy.DescriptorImpl) as.getDescriptor()).showPermission(Jenkins.RUN_SCRIPTS));
        assertFalse(((GlobalMatrixAuthorizationStrategy.DescriptorImpl) as.getDescriptor()).showPermission(PluginManager.CONFIGURE_UPDATECENTER));
        assertFalse(((GlobalMatrixAuthorizationStrategy.DescriptorImpl) as.getDescriptor()).showPermission(PluginManager.UPLOAD_PLUGINS));
    }
}
