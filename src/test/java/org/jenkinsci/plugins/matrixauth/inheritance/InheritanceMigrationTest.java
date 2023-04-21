package org.jenkinsci.plugins.matrixauth.inheritance;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.User;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

public class InheritanceMigrationTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    @LocalData
    @SuppressWarnings("deprecation")
    public void testInheritanceMigration() throws Exception {
        Assert.assertTrue(j.jenkins.getAuthorizationStrategy() instanceof ProjectMatrixAuthorizationStrategy);

        {
            Folder folder = (Folder) j.jenkins.getItemByFullName("folder");
            Assert.assertNotNull(folder);
            Assert.assertTrue(folder.getConfigFile().asString().contains("blocksInheritance"));
            AuthorizationMatrixProperty prop = (folder).getProperties().get(AuthorizationMatrixProperty.class);
            Assert.assertTrue(prop.isBlocksInheritance());
            Assert.assertTrue(prop.getInheritanceStrategy() instanceof NonInheritingStrategy);
            Assert.assertTrue(prop.hasExplicitPermission("admin", Item.CONFIGURE));
            Assert.assertTrue(prop.hasExplicitPermission("admin", Item.READ));
            Assert.assertTrue(prop.hasExplicitPermission("admin", Item.CREATE));
            Assert.assertFalse(folder.getACL().hasPermission(User.get("alice").impersonate(), Item.READ));
            Assert.assertFalse(folder.getACL().hasPermission(User.get("bob").impersonate(), Item.READ));
            folder.save();
            Assert.assertFalse(folder.getConfigFile().asString().contains("blocksInheritance"));

            folder = (Folder) j.jenkins.getItemByFullName("folder1");
            Assert.assertNotNull(folder);
            Assert.assertTrue(folder.getConfigFile().asString().contains("blocksInheritance"));
            prop = (folder).getProperties().get(AuthorizationMatrixProperty.class);
            Assert.assertTrue(prop.isBlocksInheritance());
            Assert.assertTrue(prop.getInheritanceStrategy() instanceof NonInheritingStrategy);
            Assert.assertTrue(prop.hasExplicitPermission("admin", Item.CONFIGURE));
            Assert.assertFalse(prop.hasExplicitPermission("admin", Item.READ));
            Assert.assertTrue(folder.getACL()
                    .hasPermission(
                            User.get("admin").impersonate(),
                            Item.READ)); // change from before (JENKINS-24878/JENKINS-37904)
            Assert.assertTrue(folder.getACL().hasPermission(User.get("admin").impersonate(), Item.CONFIGURE));
            Assert.assertTrue(prop.hasExplicitPermission("alice", Item.CONFIGURE));
            Assert.assertTrue(prop.hasExplicitPermission("alice", Item.READ));
            Assert.assertTrue(folder.getACL().hasPermission(User.get("alice").impersonate(), Item.READ));
            Assert.assertFalse(prop.hasPermission("bob", Item.READ));
            Assert.assertFalse(folder.getACL().hasPermission(User.get("bob").impersonate(), Item.READ));
            folder.save();
            Assert.assertFalse(folder.getConfigFile().asString().contains("blocksInheritance"));
        }

        {
            Job<?, ?> job = (Job<?, ?>) j.jenkins.getItemByFullName("folder/inheritNone");
            Assert.assertNotNull(job);
            Assert.assertTrue(job.getConfigFile().asString().contains("blocksInheritance"));
            hudson.security.AuthorizationMatrixProperty prop =
                    job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
            Assert.assertTrue(prop.isBlocksInheritance());
            Assert.assertEquals(0, prop.getGrantedPermissions().size());
            Assert.assertTrue(prop.getInheritanceStrategy() instanceof NonInheritingStrategy);
            Assert.assertTrue(job.getACL()
                    .hasPermission(
                            User.get("admin").impersonate(),
                            Item.READ)); // change from before (JENKINS-24878/JENKINS-37904)
            job.save();
            Assert.assertFalse(job.getConfigFile().asString().contains("blocksInheritance"));

            job = (Job<?, ?>) j.jenkins.getItemByFullName("job");
            Assert.assertNotNull(job);
            Assert.assertTrue(job.getConfigFile().asString().contains("blocksInheritance"));
            prop = job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
            Assert.assertFalse(prop.isBlocksInheritance());
            Assert.assertTrue(prop.getInheritanceStrategy() instanceof InheritParentStrategy);
            Assert.assertTrue(job.getACL().hasPermission(User.get("bob").impersonate(), Item.READ));
            Assert.assertTrue(job.getACL().hasPermission(User.get("alice").impersonate(), Item.READ));
            Assert.assertTrue(job.getACL().hasPermission(User.get("admin").impersonate(), Item.READ));
            Assert.assertTrue(job.getACL().hasPermission(User.get("admin").impersonate(), Item.CONFIGURE));
            job.save();
            Assert.assertFalse(job.getConfigFile().asString().contains("blocksInheritance"));
        }
    }
}
