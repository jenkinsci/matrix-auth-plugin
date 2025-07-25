package org.jenkinsci.plugins.matrixauth.integrations.casc;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty;
import hudson.model.Computer;
import hudson.model.Item;
import hudson.model.Node;
import hudson.security.AuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import io.jenkins.plugins.casc.ConfigurationAsCode;
import io.jenkins.plugins.casc.ConfiguratorException;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty;
import org.jenkinsci.plugins.matrixauth.AuthorizationType;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritGlobalStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.RealJenkinsExtension;

class ImportTest {

    @RegisterExtension
    private final RealJenkinsExtension rr =
            new RealJenkinsExtension().withLogger(MatrixAuthorizationStrategyConfigurator.class, Level.WARNING);

    @Test
    void v3Test() throws Throwable {
        rr.then(ImportTest::v3TestStep);
    }

    private static void v3TestStep(JenkinsRule r) throws ConfiguratorException {
        ConfigurationAsCode.get()
                .configure(Objects.requireNonNull(ImportTest.class.getResource("configuration-as-code-v3.yml"))
                        .toExternalForm());

        assertInstanceOf(HudsonPrivateSecurityRealm.class, r.jenkins.getSecurityRealm(), "security realm");
        AuthorizationStrategy authorizationStrategy = r.jenkins.getAuthorizationStrategy();
        assertInstanceOf(ProjectMatrixAuthorizationStrategy.class, authorizationStrategy, "authorization strategy");
        ProjectMatrixAuthorizationStrategy projectMatrixAuthorizationStrategy =
                (ProjectMatrixAuthorizationStrategy) authorizationStrategy;
        { // global
            final List<PermissionEntry> entries = projectMatrixAuthorizationStrategy.getAllPermissionEntries();
            assertEquals(2, entries.size(), "2 real sids (we ignore anon/user)");
            assertThat(
                    entries,
                    hasItems(
                            new PermissionEntry(AuthorizationType.GROUP, "authenticated"),
                            new PermissionEntry(AuthorizationType.EITHER, "developer")));
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.user("anonymous"), Jenkins.READ),
                    "anon can read");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.group("authenticated"), Jenkins.READ),
                    "authenticated can read");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.group("authenticated"), Item.BUILD),
                    "authenticated can build");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.group("authenticated"), Item.DELETE),
                    "authenticated can delete jobs");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.group("authenticated"), Jenkins.ADMINISTER),
                    "authenticated can administer");
        }
        { // item from Job DSL
            Folder folder = (Folder) r.jenkins.getItem("generated");
            assertNotNull(folder);
            AuthorizationMatrixProperty property = folder.getProperties().get(AuthorizationMatrixProperty.class);
            assertInstanceOf(
                    NonInheritingStrategy.class, property.getInheritanceStrategy(), "folder property inherits");
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.BUILD));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.READ));
            assertFalse(property.hasExplicitPermission(PermissionEntry.user("anonymous"), Item.READ));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.CONFIGURE));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.DELETE));
        }
        { // agent
            final Node agent = r.jenkins.getNode("agent1");
            assertNotNull(agent);
            AuthorizationMatrixNodeProperty property = agent.getNodeProperty(AuthorizationMatrixNodeProperty.class);
            assertNotNull(property);
            assertInstanceOf(InheritGlobalStrategy.class, property.getInheritanceStrategy());
            assertTrue(property.hasExplicitPermission(PermissionEntry.user("anonymous"), Computer.BUILD));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Computer.BUILD));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Computer.DISCONNECT));
        }
        assertEquals(
                0,
                Jenkins.logRecords.stream()
                        .filter(l -> l.getLoggerName().equals(MatrixAuthorizationStrategyConfigurator.class.getName()))
                        .count(),
                "no messages");
    }

    @Test
    void v2AmbiguousTest() throws Throwable {
        rr.then(ImportTest::v2AmbiguousTestStep);
    }

    private static void v2AmbiguousTestStep(JenkinsRule r) throws ConfiguratorException {
        ConfigurationAsCode.get()
                .configure(
                        Objects.requireNonNull(ImportTest.class.getResource("configuration-as-code-v2-ambiguous.yml"))
                                .toExternalForm());

        assertInstanceOf(HudsonPrivateSecurityRealm.class, r.jenkins.getSecurityRealm(), "security realm");
        AuthorizationStrategy authorizationStrategy = r.jenkins.getAuthorizationStrategy();
        assertInstanceOf(ProjectMatrixAuthorizationStrategy.class, authorizationStrategy, "authorization strategy");
        ProjectMatrixAuthorizationStrategy projectMatrixAuthorizationStrategy =
                (ProjectMatrixAuthorizationStrategy) authorizationStrategy;
        { // global
            assertEquals(
                    2,
                    projectMatrixAuthorizationStrategy.getAllPermissionEntries().size(),
                    "two ambiguous sids");
            assertThat(
                    projectMatrixAuthorizationStrategy.getAllPermissionEntries(),
                    hasItems(
                            new PermissionEntry(AuthorizationType.EITHER, "anonymous"),
                            new PermissionEntry(AuthorizationType.EITHER, "authenticated")));
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission("anonymous", Jenkins.READ),
                    "anon can read");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Jenkins.READ),
                    "authenticated can read");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Item.BUILD),
                    "authenticated can build");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Item.DELETE),
                    "authenticated can delete jobs");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Jenkins.ADMINISTER),
                    "authenticated can administer");

            assertFalse(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.user("anonymous"), Jenkins.READ),
                    "anon (user) cannot explicitly read");
            assertFalse(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.group("authenticated"), Jenkins.READ),
                    "authenticated can read");
            assertFalse(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.group("authenticated"), Item.BUILD),
                    "authenticated can build");
            assertFalse(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.group("authenticated"), Item.DELETE),
                    "authenticated can delete jobs");
            assertFalse(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.group("authenticated"), Jenkins.ADMINISTER),
                    "authenticated can administer");

            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            new PermissionEntry(AuthorizationType.EITHER, "anonymous"), Jenkins.READ),
                    "anon (either) can read");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            new PermissionEntry(AuthorizationType.EITHER, "authenticated"), Jenkins.READ),
                    "authenticated (either) can read");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            new PermissionEntry(AuthorizationType.EITHER, "authenticated"), Item.BUILD),
                    "authenticated (either) can build");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            new PermissionEntry(AuthorizationType.EITHER, "authenticated"), Item.DELETE),
                    "authenticated (either) can delete jobs");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            new PermissionEntry(AuthorizationType.EITHER, "authenticated"), Jenkins.ADMINISTER),
                    "authenticated (either) can administer");
        }
        { // item from Job DSL
            Folder folder = (Folder) r.jenkins.getItem("generated");
            assertNotNull(folder);
            AuthorizationMatrixProperty property = folder.getProperties().get(AuthorizationMatrixProperty.class);
            assertInstanceOf(
                    NonInheritingStrategy.class, property.getInheritanceStrategy(), "folder property inherits");
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
            assertInstanceOf(InheritGlobalStrategy.class, property.getInheritanceStrategy());
            assertTrue(property.hasExplicitPermission("anonymous", Computer.BUILD));
            assertTrue(property.hasExplicitPermission("authenticated", Computer.BUILD));
            assertTrue(property.hasExplicitPermission("authenticated", Computer.DISCONNECT));
        }
        assertTrue(
                Jenkins.logRecords.stream()
                        .anyMatch(l -> l.getLoggerName().equals(MatrixAuthorizationStrategyConfigurator.class.getName())
                                && l.getMessage()
                                        .contains("Loading deprecated attribute 'permissions' for instance of")),
                "correct message");
    }

    @Test
    void v2Test() throws Throwable {
        rr.then(ImportTest::v2TestStep);
    }

    private static void v2TestStep(JenkinsRule r) throws ConfiguratorException {
        ConfigurationAsCode.get()
                .configure(Objects.requireNonNull(ImportTest.class.getResource("configuration-as-code-v2.yml"))
                        .toExternalForm());

        assertInstanceOf(HudsonPrivateSecurityRealm.class, r.jenkins.getSecurityRealm(), "security realm");
        AuthorizationStrategy authorizationStrategy = r.jenkins.getAuthorizationStrategy();
        assertInstanceOf(ProjectMatrixAuthorizationStrategy.class, authorizationStrategy, "authorization strategy");
        ProjectMatrixAuthorizationStrategy projectMatrixAuthorizationStrategy =
                (ProjectMatrixAuthorizationStrategy) authorizationStrategy;
        { // global
            final List<PermissionEntry> entries = projectMatrixAuthorizationStrategy.getAllPermissionEntries();
            assertEquals(1, entries.size(), "one real sid (we ignore anon/user)");
            assertThat(entries, hasItems(new PermissionEntry(AuthorizationType.GROUP, "authenticated")));
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.user("anonymous"), Jenkins.READ),
                    "anon can read");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.group("authenticated"), Jenkins.READ),
                    "authenticated can read");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.group("authenticated"), Item.BUILD),
                    "authenticated can build");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.group("authenticated"), Item.DELETE),
                    "authenticated can delete jobs");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission(
                            PermissionEntry.group("authenticated"), Jenkins.ADMINISTER),
                    "authenticated can administer");
        }
        { // item from Job DSL
            Folder folder = (Folder) r.jenkins.getItem("generated");
            assertNotNull(folder);
            AuthorizationMatrixProperty property = folder.getProperties().get(AuthorizationMatrixProperty.class);
            assertInstanceOf(
                    NonInheritingStrategy.class, property.getInheritanceStrategy(), "folder property inherits");
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.BUILD));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.READ));
            assertFalse(property.hasExplicitPermission(PermissionEntry.user("anonymous"), Item.READ));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.CONFIGURE));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.DELETE));
        }
        { // agent
            final Node agent = r.jenkins.getNode("agent1");
            assertNotNull(agent);
            AuthorizationMatrixNodeProperty property = agent.getNodeProperty(AuthorizationMatrixNodeProperty.class);
            assertNotNull(property);
            assertInstanceOf(InheritGlobalStrategy.class, property.getInheritanceStrategy());
            assertTrue(property.hasExplicitPermission(PermissionEntry.user("anonymous"), Computer.BUILD));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Computer.BUILD));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group("authenticated"), Computer.DISCONNECT));
        }
        assertTrue(
                Jenkins.logRecords.stream()
                        .anyMatch(l -> l.getLoggerName().equals(MatrixAuthorizationStrategyConfigurator.class.getName())
                                && l.getMessage()
                                        .contains("Loading deprecated attribute 'permissions' for instance of")),
                "correct message");
    }

    @Test
    void v1Test() throws Throwable {
        rr.then(ImportTest::v1TestStep);
    }

    private static void v1TestStep(JenkinsRule r) throws ConfiguratorException {
        ConfigurationAsCode.get()
                .configure(Objects.requireNonNull(ImportTest.class.getResource("configuration-as-code-v1.yml"))
                        .toExternalForm());

        assertInstanceOf(HudsonPrivateSecurityRealm.class, r.jenkins.getSecurityRealm(), "security realm");
        AuthorizationStrategy authorizationStrategy = r.jenkins.getAuthorizationStrategy();
        assertInstanceOf(ProjectMatrixAuthorizationStrategy.class, authorizationStrategy, "authorization strategy");
        ProjectMatrixAuthorizationStrategy projectMatrixAuthorizationStrategy =
                (ProjectMatrixAuthorizationStrategy) authorizationStrategy;
        { // global
            assertEquals(
                    2,
                    projectMatrixAuthorizationStrategy.getAllPermissionEntries().size(),
                    "two ambiguous sids");
            assertThat(
                    projectMatrixAuthorizationStrategy.getAllPermissionEntries(),
                    hasItems(
                            new PermissionEntry(AuthorizationType.EITHER, "anonymous"),
                            new PermissionEntry(AuthorizationType.EITHER, "authenticated")));
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission("anonymous", Jenkins.READ),
                    "anon can read");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Jenkins.READ),
                    "authenticated can read");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Item.BUILD),
                    "authenticated can build");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Item.DELETE),
                    "authenticated can delete jobs");
            assertTrue(
                    projectMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Jenkins.ADMINISTER),
                    "authenticated can administer");
        }

        assertTrue(
                Jenkins.logRecords.stream().anyMatch(l -> l.getLoggerName()
                        .equals(MatrixAuthorizationStrategyConfigurator.class.getName())),
                "at least one warning");
        assertTrue(
                Jenkins.logRecords.stream()
                        .anyMatch(l -> l.getLoggerName().equals(MatrixAuthorizationStrategyConfigurator.class.getName())
                                && l.getMessage()
                                        .contains("Loading deprecated attribute 'grantedPermissions' for instance")),
                "correct message");
    }
}
