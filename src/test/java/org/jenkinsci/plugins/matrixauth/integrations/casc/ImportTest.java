package org.jenkinsci.plugins.matrixauth.integrations.casc;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty;
import hudson.model.Computer;
import hudson.model.Item;
import hudson.security.AuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty;
import org.jenkinsci.plugins.matrixauth.AuthorizationType;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritGlobalStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.junit.Rule;
import org.junit.Test;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import org.jvnet.hudson.test.LoggerRule;

import java.util.List;
import java.util.logging.Level;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ImportTest {

    @Rule
    public JenkinsConfiguredWithCodeRule r = new JenkinsConfiguredWithCodeRule();

    @Rule
    public LoggerRule l = new LoggerRule().record(MatrixAuthorizationStrategyConfigurator.class, Level.WARNING).capture(20);

    @Test
    @ConfiguredWithCode("configuration-as-code-ambiguous.yml")
    public void should_support_configuration_as_code_ambiguous_format() throws Exception {
        assertTrue("security realm", r.jenkins.getSecurityRealm() instanceof HudsonPrivateSecurityRealm);
        AuthorizationStrategy authorizationStrategy = r.jenkins.getAuthorizationStrategy();
        assertTrue("authorization strategy", authorizationStrategy instanceof ProjectMatrixAuthorizationStrategy);
        ProjectMatrixAuthorizationStrategy projectMatrixAuthorizationStrategy = (ProjectMatrixAuthorizationStrategy) authorizationStrategy;
        { // global
            assertEquals("two ambiguous sids", 2, projectMatrixAuthorizationStrategy.getAllPermissionEntries().size());
            assertThat(projectMatrixAuthorizationStrategy.getAllPermissionEntries(), hasItems(new PermissionEntry(AuthorizationType.EITHER, "anonymous"), new PermissionEntry(AuthorizationType.EITHER, "authenticated")));
            assertTrue("anon can read", projectMatrixAuthorizationStrategy.hasExplicitPermission("anonymous", Jenkins.READ));
            assertTrue("authenticated can read", projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Jenkins.READ));
            assertTrue("authenticated can build", projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Item.BUILD));
            assertTrue("authenticated can delete jobs", projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Item.DELETE));
            assertTrue("authenticated can administer", projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Jenkins.ADMINISTER));

            assertFalse("anon (user) cannot explicitly read", projectMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.user("anonymous"), Jenkins.READ));
            assertFalse("authenticated can read", projectMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.group("authenticated"), Jenkins.READ));
            assertFalse("authenticated can build", projectMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.BUILD));
            assertFalse("authenticated can delete jobs", projectMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.DELETE));
            assertFalse("authenticated can administer", projectMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.group("authenticated"), Jenkins.ADMINISTER));

            assertTrue("anon (either) can read", projectMatrixAuthorizationStrategy.hasExplicitPermission(new PermissionEntry(AuthorizationType.EITHER, "anonymous"), Jenkins.READ));
            assertTrue("authenticated (either) can read", projectMatrixAuthorizationStrategy.hasExplicitPermission(new PermissionEntry(AuthorizationType.EITHER, "authenticated"), Jenkins.READ));
            assertTrue("authenticated (either) can build", projectMatrixAuthorizationStrategy.hasExplicitPermission(new PermissionEntry(AuthorizationType.EITHER, "authenticated"), Item.BUILD));
            assertTrue("authenticated (either) can delete jobs", projectMatrixAuthorizationStrategy.hasExplicitPermission(new PermissionEntry(AuthorizationType.EITHER, "authenticated"), Item.DELETE));
            assertTrue("authenticated (either) can administer", projectMatrixAuthorizationStrategy.hasExplicitPermission(new PermissionEntry(AuthorizationType.EITHER, "authenticated"), Jenkins.ADMINISTER));
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
        assertEquals("no warnings", 0, l.getMessages().size());
    }

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    public void should_support_configuration_as_code() throws Exception {
        assertTrue("security realm", r.jenkins.getSecurityRealm() instanceof HudsonPrivateSecurityRealm);
        AuthorizationStrategy authorizationStrategy = r.jenkins.getAuthorizationStrategy();
        assertTrue("authorization strategy", authorizationStrategy instanceof ProjectMatrixAuthorizationStrategy);
        ProjectMatrixAuthorizationStrategy projectMatrixAuthorizationStrategy = (ProjectMatrixAuthorizationStrategy) authorizationStrategy;
        { // global
            final List<PermissionEntry> entries = projectMatrixAuthorizationStrategy.getAllPermissionEntries();
            assertEquals("one real sid (we ignore anon/user)", 1, entries.size());
            assertThat(entries, hasItems(new PermissionEntry(AuthorizationType.GROUP, "authenticated")));
            assertTrue("anon can read", projectMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.user("anonymous"), Jenkins.READ));
            assertTrue("authenticated can read", projectMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.group("authenticated"), Jenkins.READ));
            assertTrue("authenticated can build", projectMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.BUILD));
            assertTrue("authenticated can delete jobs", projectMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.DELETE));
            assertTrue("authenticated can administer", projectMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.group("authenticated"), Jenkins.ADMINISTER));
        }
        { // item from Job DSL
            Folder folder = (Folder) r.jenkins.getItem("generated");
            AuthorizationMatrixProperty property = folder.getProperties().get(AuthorizationMatrixProperty.class);
            assertTrue("folder property inherits", property.getInheritanceStrategy() instanceof NonInheritingStrategy);
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.BUILD));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.READ));
            assertFalse(property.hasExplicitPermission(PermissionEntry.user("anonymous"), Item.READ));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.CONFIGURE));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.DELETE));
        }
        { // agent
            AuthorizationMatrixNodeProperty property = r.jenkins.getNode("agent1").getNodeProperty(AuthorizationMatrixNodeProperty.class);
            assertTrue(property.getInheritanceStrategy() instanceof InheritGlobalStrategy);
            assertTrue(property.hasExplicitPermission(PermissionEntry.user("anonymous"), Computer.BUILD));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Computer.BUILD));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Computer.DISCONNECT));
        }
        assertEquals("no warnings", 0, l.getMessages().size());
    }

    @Test
    @ConfiguredWithCode("legacy-format.yml")
    public void legacyTest() throws Exception {
        assertTrue("security realm", r.jenkins.getSecurityRealm() instanceof HudsonPrivateSecurityRealm);
        AuthorizationStrategy authorizationStrategy = r.jenkins.getAuthorizationStrategy();
        assertTrue("authorization strategy", authorizationStrategy instanceof ProjectMatrixAuthorizationStrategy);
        ProjectMatrixAuthorizationStrategy projectMatrixAuthorizationStrategy = (ProjectMatrixAuthorizationStrategy) authorizationStrategy;
        { // global
            assertEquals("two ambiguous sids", 2, projectMatrixAuthorizationStrategy.getAllPermissionEntries().size());
            assertThat(projectMatrixAuthorizationStrategy.getAllPermissionEntries(), hasItems(new PermissionEntry(AuthorizationType.EITHER, "anonymous"), new PermissionEntry(AuthorizationType.EITHER, "authenticated")));
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
