package org.jenkinsci.plugins.matrixauth;

import hudson.security.AuthorizationStrategy;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.casc.ConfigurationAsCode;
import org.jenkinsci.plugins.casc.Configurator;
import org.jenkinsci.plugins.matrixauth.casc.ProjectMatrixAuthorizationStrategyConfigurator;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Created by mads on 2/22/18.
 */
public class ConfigurationAsCodeTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void shouldReturnCustomConfigurator() {
        Configurator configurator = Configurator.lookup(ProjectMatrixAuthorizationStrategy.class);
        assertNotNull("Failed to find configurator for ProjectMatrixAuthorizationStrategy", configurator);
        assertEquals("Retrieved wrong configurator", ProjectMatrixAuthorizationStrategyConfigurator.class, configurator.getClass());
    }

    @Test
    public void shouldReturnCustomConfiguratorForBaseType() {
        Configurator c = Configurator.lookupForBaseType(AuthorizationStrategy.class, "projectMatrix");
        assertNotNull("Failed to find configurator for ProjectMatrixAuthorizationStrategy", c);
        assertEquals("Retrieved wrong configurator", ProjectMatrixAuthorizationStrategyConfigurator.class, c.getClass());
        Configurator.lookup(ProjectMatrixAuthorizationStrategy.class);
    }

    @Test
    public void checkCorrectlyConfiguredPermissions() throws Exception {
        ConfigurationAsCode.get().configure(getClass().getResource("Configuration-as-Code.yml").toExternalForm());

        assertEquals("The configured instance must use the Global Matrix Authentication Strategy", ProjectMatrixAuthorizationStrategy.class, Jenkins.getInstance().getAuthorizationStrategy().getClass());
        ProjectMatrixAuthorizationStrategy gms = (ProjectMatrixAuthorizationStrategy) Jenkins.getInstance().getAuthorizationStrategy();

        List<String> adminPermission = new ArrayList<>(gms.getGrantedPermissions().get(Jenkins.ADMINISTER));
        assertEquals("authenticated", adminPermission.get(0));

        List<String> readPermission = new ArrayList<>(gms.getGrantedPermissions().get(Jenkins.READ));
        assertEquals("anonymous", readPermission.get(0));
    }
}
