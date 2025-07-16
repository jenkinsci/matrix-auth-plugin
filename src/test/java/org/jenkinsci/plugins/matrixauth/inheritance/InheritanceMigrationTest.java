package org.jenkinsci.plugins.matrixauth.inheritance;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty;
import hudson.XmlFile;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.User;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

@WithJenkins
class InheritanceMigrationTest {

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
    }

    @Test
    @LocalData
    @SuppressWarnings("deprecation")
    void testInheritanceMigration() throws Exception {
        assertInstanceOf(ProjectMatrixAuthorizationStrategy.class, j.jenkins.getAuthorizationStrategy());

        {
            Folder folder = (Folder) j.jenkins.getItemByFullName("folder");
            assertNotNull(folder);
            assertTrue(folder.getConfigFile().asString().contains("blocksInheritance"));
            AuthorizationMatrixProperty prop = (folder).getProperties().get(AuthorizationMatrixProperty.class);
            assertTrue(prop.isBlocksInheritance());
            assertInstanceOf(NonInheritingStrategy.class, prop.getInheritanceStrategy());
            assertTrue(prop.hasExplicitPermission("admin", Item.CONFIGURE));
            assertTrue(prop.hasExplicitPermission("admin", Item.READ));
            assertTrue(prop.hasExplicitPermission("admin", Item.CREATE));
            assertFalse(folder.getACL().hasPermission(User.get("alice").impersonate(), Item.READ));
            assertFalse(folder.getACL().hasPermission(User.get("bob").impersonate(), Item.READ));
            folder.save();
            assertFalse(folder.getConfigFile().asString().contains("blocksInheritance"));

            folder = (Folder) j.jenkins.getItemByFullName("folder1");
            assertNotNull(folder);
            assertTrue(folder.getConfigFile().asString().contains("blocksInheritance"));
            prop = (folder).getProperties().get(AuthorizationMatrixProperty.class);
            assertTrue(prop.isBlocksInheritance());
            assertInstanceOf(NonInheritingStrategy.class, prop.getInheritanceStrategy());
            assertTrue(prop.hasExplicitPermission("admin", Item.CONFIGURE));
            assertFalse(prop.hasExplicitPermission("admin", Item.READ));
            assertTrue(folder.getACL()
                    .hasPermission(
                            User.get("admin").impersonate(),
                            Item.READ)); // change from before (JENKINS-24878/JENKINS-37904)
            assertTrue(folder.getACL().hasPermission(User.get("admin").impersonate(), Item.CONFIGURE));
            assertTrue(prop.hasExplicitPermission("alice", Item.CONFIGURE));
            assertTrue(prop.hasExplicitPermission("alice", Item.READ));
            assertTrue(folder.getACL().hasPermission(User.get("alice").impersonate(), Item.READ));
            assertFalse(prop.hasPermission("bob", Item.READ));
            assertFalse(folder.getACL().hasPermission(User.get("bob").impersonate(), Item.READ));
            folder.save();
            assertFalse(folder.getConfigFile().asString().contains("blocksInheritance"));
        }

        {
            Job<?, ?> job = (Job<?, ?>) j.jenkins.getItemByFullName("folder/inheritNone");
            assertNotNull(job);
            XmlFile configFile = job.getConfigFile();
            assertThat("correct contents of " + configFile, configFile.asString(), containsString("blocksInheritance"));
            hudson.security.AuthorizationMatrixProperty prop =
                    job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
            assertTrue(prop.isBlocksInheritance());
            assertEquals(0, prop.getGrantedPermissions().size());
            assertInstanceOf(NonInheritingStrategy.class, prop.getInheritanceStrategy());
            assertTrue(job.getACL()
                    .hasPermission(
                            User.get("admin").impersonate(),
                            Item.READ)); // change from before (JENKINS-24878/JENKINS-37904)
            job.save();
            assertFalse(job.getConfigFile().asString().contains("blocksInheritance"));

            job = (Job<?, ?>) j.jenkins.getItemByFullName("job");
            assertNotNull(job);
            assertTrue(job.getConfigFile().asString().contains("blocksInheritance"));
            prop = job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
            assertFalse(prop.isBlocksInheritance());
            assertInstanceOf(InheritParentStrategy.class, prop.getInheritanceStrategy());
            assertTrue(job.getACL().hasPermission(User.get("bob").impersonate(), Item.READ));
            assertTrue(job.getACL().hasPermission(User.get("alice").impersonate(), Item.READ));
            assertTrue(job.getACL().hasPermission(User.get("admin").impersonate(), Item.READ));
            assertTrue(job.getACL().hasPermission(User.get("admin").impersonate(), Item.CONFIGURE));
            job.save();
            assertFalse(job.getConfigFile().asString().contains("blocksInheritance"));
        }
    }
}
