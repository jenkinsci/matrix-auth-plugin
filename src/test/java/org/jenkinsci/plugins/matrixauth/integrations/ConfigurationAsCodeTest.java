package org.jenkinsci.plugins.matrixauth.integrations;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty;
import hudson.model.Computer;
import hudson.model.Item;
import hudson.security.AuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritGlobalStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.junit.Rule;
import org.junit.Test;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;

import static org.junit.Assert.*;

public class ConfigurationAsCodeTest {

    @Rule
    public JenkinsConfiguredWithCodeRule r = new JenkinsConfiguredWithCodeRule();

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    public void should_support_configuration_as_code() throws Exception {
        assertTrue("security realm", r.jenkins.getSecurityRealm() instanceof HudsonPrivateSecurityRealm);
        AuthorizationStrategy authorizationStrategy = r.jenkins.getAuthorizationStrategy();
        assertTrue("authorization strategy", authorizationStrategy instanceof ProjectMatrixAuthorizationStrategy);
        ProjectMatrixAuthorizationStrategy projectMatrixAuthorizationStrategy = (ProjectMatrixAuthorizationStrategy) authorizationStrategy;
        { // global
            assertEquals("one real user sid", 1, projectMatrixAuthorizationStrategy.getAllSIDs().size());
            assertTrue("anon can read", projectMatrixAuthorizationStrategy.hasExplicitPermission("anonymous", Jenkins.READ));
        }
        { // item from Job DSL
            Folder folder = (Folder) r.jenkins.getItem("generated");
            AuthorizationMatrixProperty property = folder.getProperties().get(AuthorizationMatrixProperty.class);
            assertTrue("folder property inherits", property.getInheritanceStrategy() instanceof NonInheritingStrategy);
            assertTrue(property.hasExplicitPermission("authenticated", Item.BUILD));
            assertTrue(property.hasExplicitPermission("authenticated", Item.READ));
            assertFalse(property.hasExplicitPermission("anonymous", Item.READ));
            assertTrue(property.hasExplicitPermission("authenticated", Item.CONFIGURE));
            assertTrue(property.hasExplicitPermission("authenticated", Item.DELETE));
        }
        { // agent
            AuthorizationMatrixNodeProperty property = r.jenkins.getNode("agent1").getNodeProperty(AuthorizationMatrixNodeProperty.class);
            assertTrue(property.getInheritanceStrategy() instanceof InheritGlobalStrategy);
            assertTrue(property.hasExplicitPermission("anonymous", Computer.BUILD));
            assertTrue(property.hasExplicitPermission("authenticated", Computer.BUILD));
            assertTrue(property.hasExplicitPermission("authenticated", Computer.DISCONNECT));
        }
    }
}
