package org.jenkinsci.plugins.matrixauth.inheritance;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
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
    public void testInheritanceMigration() throws Exception {
        Assert.assertTrue(j.jenkins.getAuthorizationStrategy() instanceof ProjectMatrixAuthorizationStrategy);
        ProjectMatrixAuthorizationStrategy strategy = (ProjectMatrixAuthorizationStrategy) j.jenkins.getAuthorizationStrategy();

        {
            Folder folder = (Folder) j.jenkins.getItemByFullName("folder");
            AuthorizationMatrixProperty prop = (folder).getProperties().get(AuthorizationMatrixProperty.class);
            Assert.assertTrue(prop.isBlocksInheritance());
            Assert.assertTrue(prop.getInheritanceStrategy() instanceof NonInheritingStrategy);
            Assert.assertTrue(prop.hasExplicitPermission("admin", Item.CONFIGURE));
            Assert.assertTrue(prop.hasExplicitPermission("admin", Item.READ));
            Assert.assertTrue(prop.hasExplicitPermission("admin", Item.CREATE));
            Assert.assertFalse(folder.getACL().hasPermission(User.get("alice").impersonate(), Item.READ));
            Assert.assertFalse(folder.getACL().hasPermission(User.get("bob").impersonate(), Item.READ));

            folder = (Folder) j.jenkins.getItemByFullName("folder1");
            prop = (folder).getProperties().get(AuthorizationMatrixProperty.class);
            Assert.assertTrue(prop.isBlocksInheritance());
            Assert.assertTrue(prop.getInheritanceStrategy() instanceof NonInheritingStrategy);
            Assert.assertTrue(prop.hasExplicitPermission("admin", Item.CONFIGURE));
            Assert.assertFalse(prop.hasExplicitPermission("admin", Item.READ));
            Assert.assertTrue(folder.getACL().hasPermission(User.get("admin").impersonate(), Item.READ)); // change from before (JENKINS-24878/JENKINS-37904)
            Assert.assertTrue(folder.getACL().hasPermission(User.get("admin").impersonate(), Item.CONFIGURE));
            Assert.assertTrue(prop.hasExplicitPermission("alice", Item.CONFIGURE));
            Assert.assertTrue(prop.hasExplicitPermission("alice", Item.READ));
            Assert.assertTrue(folder.getACL().hasPermission(User.get("alice").impersonate(), Item.READ));
            Assert.assertFalse(prop.hasPermission("bob", Item.READ));
            Assert.assertFalse(folder.getACL().hasPermission(User.get("bob").impersonate(), Item.READ));
        }

        {
            Job job = (Job) j.jenkins.getItemByFullName("folder/inheritNone");
            hudson.security.AuthorizationMatrixProperty prop = (hudson.security.AuthorizationMatrixProperty) job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
            Assert.assertTrue(prop.isBlocksInheritance());
            Assert.assertEquals(0, prop.getGrantedPermissions().size());
            Assert.assertTrue(prop.getInheritanceStrategy() instanceof NonInheritingStrategy);
            Assert.assertTrue(job.getACL().hasPermission(User.get("admin").impersonate(), Item.READ)); // change from before (JENKINS-24878/JENKINS-37904)

            job = (Job) j.jenkins.getItemByFullName("job");
            prop = (hudson.security.AuthorizationMatrixProperty) job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
            Assert.assertFalse(prop.isBlocksInheritance());
            Assert.assertTrue(prop.getInheritanceStrategy() instanceof InheritParentStrategy);
            Assert.assertTrue(job.getACL().hasPermission(User.get("bob").impersonate(), Item.READ));
            Assert.assertTrue(job.getACL().hasPermission(User.get("alice").impersonate(), Item.READ));
            Assert.assertTrue(job.getACL().hasPermission(User.get("admin").impersonate(), Item.READ));
            Assert.assertTrue(job.getACL().hasPermission(User.get("admin").impersonate(), Item.CONFIGURE));
        }
    }
}
