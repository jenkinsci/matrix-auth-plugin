package org.jenkinsci.plugins.matrixauth;

import hudson.security.ProjectMatrixAuthorizationStrategy;
import io.jenkins.plugins.casc.ConfigurationAsCode;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * Created by mads on 2/22/18.
 */
public class ConfigurationAsCodeTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void should_configure_permissions() throws Exception {
        ConfigurationAsCode.get().configure(getClass().getResource("Configuration-as-Code.yml").toExternalForm());

        assertEquals("The configured instance must use the Global Matrix Authentication Strategy", ProjectMatrixAuthorizationStrategy.class, Jenkins.getInstance().getAuthorizationStrategy().getClass());
        ProjectMatrixAuthorizationStrategy gms = (ProjectMatrixAuthorizationStrategy) Jenkins.getInstance().getAuthorizationStrategy();

        List<String> adminPermission = new ArrayList<>(gms.getGrantedPermissions().get(Jenkins.ADMINISTER));
        assertEquals("authenticated", adminPermission.get(0));

        List<String> readPermission = new ArrayList<>(gms.getGrantedPermissions().get(Jenkins.READ));
        assertEquals("anonymous", readPermission.get(0));
    }
}
