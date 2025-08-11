package org.jenkinsci.plugins.matrixauth.integrations.casc;

import static io.jenkins.plugins.casc.misc.Util.toStringFromYamlFile;
import static io.jenkins.plugins.casc.misc.Util.toYamlString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import hudson.model.Node;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.Configurator;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.model.CNode;
import java.util.Objects;
import org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

@WithJenkins
class ExportTest {

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
    }

    @Test
    @LocalData
    void exportTestLegacy() throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);

        { // global configuration
            ProjectMatrixAuthorizationStrategy authorizationStrategy =
                    (ProjectMatrixAuthorizationStrategy) j.jenkins.getAuthorizationStrategy();
            Configurator<ProjectMatrixAuthorizationStrategy> c =
                    context.lookupOrFail(ProjectMatrixAuthorizationStrategy.class);

            CNode node = c.describe(authorizationStrategy, context);
            assertEquals(
                    toStringFromYamlFile(
                            this,
                            "/org/jenkinsci/plugins/matrixauth/integrations/casc/ExportTest/ExportTest-exportTestLegacy-global.yml"),
                    toYamlString(node));
        }

        { // node configuration
            Configurator<AuthorizationMatrixNodeProperty> c =
                    context.lookupOrFail(AuthorizationMatrixNodeProperty.class);
            final Node agent1 = j.jenkins.getNode("agent1");
            assertNotNull(agent1);
            AuthorizationMatrixNodeProperty nodeProperty =
                    agent1.getNodeProperty(AuthorizationMatrixNodeProperty.class);

            CNode node = c.describe(nodeProperty, context);
            assertEquals(
                    toStringFromYamlFile(
                            this,
                            "/org/jenkinsci/plugins/matrixauth/integrations/casc/ExportTest/ExportTest-exportTestLegacy-node.yml"),
                    toYamlString(node));
        }
    }

    @Test
    @LocalData
    void exportTest() throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);

        { // global configuration
            ProjectMatrixAuthorizationStrategy authorizationStrategy =
                    (ProjectMatrixAuthorizationStrategy) j.jenkins.getAuthorizationStrategy();
            Configurator<ProjectMatrixAuthorizationStrategy> c =
                    context.lookupOrFail(ProjectMatrixAuthorizationStrategy.class);

            CNode node = c.describe(authorizationStrategy, context);
            assertEquals(
                    toStringFromYamlFile(
                            this,
                            "/org/jenkinsci/plugins/matrixauth/integrations/casc/ExportTest/ExportTest-exportTest-global.yml"),
                    toYamlString(node));
        }

        { // node configuration
            Configurator<AuthorizationMatrixNodeProperty> c =
                    context.lookupOrFail(AuthorizationMatrixNodeProperty.class);
            AuthorizationMatrixNodeProperty nodeProperty = Objects.requireNonNull(j.jenkins.getNode("agent1"))
                    .getNodeProperty(AuthorizationMatrixNodeProperty.class);

            CNode node = c.describe(nodeProperty, context);
            assertEquals(
                    toStringFromYamlFile(
                            this,
                            "/org/jenkinsci/plugins/matrixauth/integrations/casc/ExportTest/ExportTest-exportTest-node.yml"),
                    toYamlString(node));
        }
    }
}
