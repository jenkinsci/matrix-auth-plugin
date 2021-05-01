package org.jenkinsci.plugins.matrixauth.integrations.casc;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty;
import hudson.model.Computer;
import hudson.model.Item;
import hudson.model.Node;
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
import org.jvnet.hudson.test.LoggerRule;

import java.util.logging.Level;

import static org.junit.Assert.*;

public class ImportTest {

    @Rule
    public JenkinsConfiguredWithCodeRule r = new JenkinsConfiguredWithCodeRule();

    @Rule
    public LoggerRule l = new LoggerRule().record(MatrixAuthorizationStrategyConfigurator.class, Level.WARNING).capture(20);

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    public void should_support_configuration_as_code() {
        assertTrue("security realm", r.jenkins.getSecurityRealm() instanceof HudsonPrivateSecurityRealm);
        AuthorizationStrategy authorizationStrategy = r.jenkins.getAuthorizationStrategy();
        assertTrue("authorization strategy", authorizationStrategy instanceof ProjectMatrixAuthorizationStrategy);
        ProjectMatrixAuthorizationStrategy projectMatrixAuthorizationStrategy = (ProjectMatrixAuthorizationStrategy) authorizationStrategy;
        { // global
            assertEquals("one real user sid", 1, projectMatrixAuthorizationStrategy.getAllSIDs().size());
            assertTrue("anon can read", projectMatrixAuthorizationStrategy.hasExplicitPermission("anonymous", Jenkins.READ));
            assertTrue("authenticated can read", projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Jenkins.READ));
            assertTrue("authenticated can build", projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Item.BUILD));
            assertTrue("authenticated can delete jobs", projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Item.DELETE));
            assertTrue("authenticated can administer", projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Jenkins.ADMINISTER));
        }
        { // item from Job DSL
            Folder folder = (Folder) r.jenkins.getItem("generated");
            assertNotNull(folder);
            AuthorizationMatrixProperty property = folder.getProperties().get(AuthorizationMatrixProperty.class);
            assertTrue("folder property inherits", property.getInheritanceStrategy() instanceof NonInheritingStrategy);
            assertTrue(property.hasExplicitPermission("authenticated", Item.BUILD));
            assertTrue(property.hasExplicitPermission("authenticated", Item.READ));
            assertFalse(property.hasExplicitPermission("anonymous", Item.READ));
            assertTrue(property.hasExplicitPermission("authenticated", Item.CONFIGURE));
            assertTrue(property.hasExplicitPermission("authenticated", Item.DELETE));
        }
        { // agent
            final Node agent1 = r.jenkins.getNode("agent1");
            assertNotNull(agent1);
            AuthorizationMatrixNodeProperty property = agent1.getNodeProperty(AuthorizationMatrixNodeProperty.class);
            assertNotNull(property);
            assertTrue(property.getInheritanceStrategy() instanceof InheritGlobalStrategy);
            assertTrue(property.hasExplicitPermission("anonymous", Computer.BUILD));
            assertTrue(property.hasExplicitPermission("authenticated", Computer.BUILD));
            assertTrue(property.hasExplicitPermission("authenticated", Computer.DISCONNECT));
        }
        assertEquals("no warnings", 0, l.getMessages().size());
    }

    @Test
    @ConfiguredWithCode("legacy-format.yml")
    public void legacyTest() {
        assertTrue("security realm", r.jenkins.getSecurityRealm() instanceof HudsonPrivateSecurityRealm);
        AuthorizationStrategy authorizationStrategy = r.jenkins.getAuthorizationStrategy();
        assertTrue("authorization strategy", authorizationStrategy instanceof ProjectMatrixAuthorizationStrategy);
        ProjectMatrixAuthorizationStrategy projectMatrixAuthorizationStrategy = (ProjectMatrixAuthorizationStrategy) authorizationStrategy;
        { // global
            assertEquals("one real user sid", 1, projectMatrixAuthorizationStrategy.getAllSIDs().size());
            assertTrue("anon can read", projectMatrixAuthorizationStrategy.hasExplicitPermission("anonymous", Jenkins.READ));
            assertTrue("authenticated can read", projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Jenkins.READ));
            assertTrue("authenticated can build", projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Item.BUILD));
            assertTrue("authenticated can delete jobs", projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Item.DELETE));
            assertTrue("authenticated can administer", projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Jenkins.ADMINISTER));
        }

        assertTrue("at least one warning", 0 < l.getMessages().size()); // seems to be called twice?
        assertTrue("correct message", l.getMessages().get(0).contains("Loading deprecated attribute 'grantedPermissions' for instance"));
    }
}
