package org.jenkinsci.plugins.matrixauth.integrations.casc;

import hudson.model.Node;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.Configurator;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.model.CNode;
import io.jenkins.plugins.casc.model.Mapping;
import org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class ExportTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    @LocalData
    public void exportTest() throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);

        { // global configuration
            ProjectMatrixAuthorizationStrategy authorizationStrategy = (ProjectMatrixAuthorizationStrategy) j.jenkins.getAuthorizationStrategy();
            Configurator<ProjectMatrixAuthorizationStrategy> c = context.lookupOrFail(ProjectMatrixAuthorizationStrategy.class);

            CNode node = c.describe(authorizationStrategy, context);
            assertNotNull(node);
            Mapping mapping = node.asMapping();

            List<CNode> permissions = mapping.get("permissions").asSequence();
            assertEquals("list size", 18, permissions.size());

            assertNull("no grantedPermissions", mapping.get("grantedPermissions"));
        }

        { // node configuration
            Configurator<AuthorizationMatrixNodeProperty> c = context.lookupOrFail(AuthorizationMatrixNodeProperty.class);
            final Node agent1 = j.jenkins.getNode("agent1");
            assertNotNull(agent1);
            AuthorizationMatrixNodeProperty nodeProperty = agent1.getNodeProperty(AuthorizationMatrixNodeProperty.class);

            CNode node = c.describe(nodeProperty, context);
            assertNotNull(node);
            Mapping mapping = node.asMapping();

            assertEquals("inheritance strategy", mapping.getScalarValue("inheritanceStrategy"), "inheritingGlobal");
            List<CNode> permissions = mapping.get("permissions").asSequence();
            assertEquals("list size", 6, permissions.size());

            {
                List<String> strings = Arrays.asList(
                        "Agent/Build:anonymous", "Agent/Build:authenticated", "Agent/Configure:authenticated",
                        "Agent/Connect:authenticated", "Agent/Delete:authenticated", "Agent/Disconnect:authenticated");
                for (CNode entry : permissions) {
                    String value = entry.asScalar().getValue();
                    assertTrue("list contains entry", strings.contains(value));
                }
            }
        }
    }
}
