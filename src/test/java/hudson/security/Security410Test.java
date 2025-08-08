package hudson.security;

import static org.junit.jupiter.api.Assertions.assertFalse;

import hudson.PluginManager;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class Security410Test {

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
    }

    @Issue("SECURITY-410")
    @Test
    @SuppressWarnings("deprecation")
    void dangerousPermissions1() {
        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        assertFalse(((GlobalMatrixAuthorizationStrategy.DescriptorImpl) as.getDescriptor())
                .showPermission(Jenkins.RUN_SCRIPTS));
        assertFalse(((GlobalMatrixAuthorizationStrategy.DescriptorImpl) as.getDescriptor())
                .showPermission(PluginManager.CONFIGURE_UPDATECENTER));
        assertFalse(((GlobalMatrixAuthorizationStrategy.DescriptorImpl) as.getDescriptor())
                .showPermission(PluginManager.UPLOAD_PLUGINS));
    }
}
