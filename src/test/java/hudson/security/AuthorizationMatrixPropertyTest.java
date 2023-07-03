package hudson.security;

import hudson.model.Item;
import hudson.scm.SCM;
import java.util.Collections;
import java.util.logging.Level;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainer;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.cps.SnippetizerTester;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.multibranch.JobPropertyStep;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;

public class AuthorizationMatrixPropertyTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Rule
    public LoggerRule l = new LoggerRule();

    @Test
    public void testSnippetizer() throws Exception {
        AuthorizationMatrixProperty property =
                new AuthorizationMatrixProperty(Collections.emptyMap(), new InheritParentStrategy());
        property.add(Item.CONFIGURE, "alice");
        property.add(Item.READ, "bob");
        property.add(Item.READ, "alice");
        property.add(SCM.TAG, "bob"); // use this to test for JENKINS-17200 robustness
        property.setInheritanceStrategy(new NonInheritingStrategy());
        SnippetizerTester tester = new SnippetizerTester(j);
        tester.assertRoundTrip(
                new JobPropertyStep(Collections.singletonList(property)),
                "properties([authorizationMatrix(inheritanceStrategy: nonInheriting(), "
                        + "permissions: ['hudson.model.Item.Configure:alice', 'hudson.model.Item.Read:alice', 'hudson.model.Item.Read:bob', 'hudson.scm.SCM.Tag:bob'])])");
    }

    @Test
    public void testSnippetizer2() throws Exception {
        AuthorizationMatrixProperty property =
                new AuthorizationMatrixProperty(Collections.emptyMap(), new InheritParentStrategy());
        property.add(Item.CONFIGURE, PermissionEntry.user("alice"));
        property.add(Item.READ, PermissionEntry.user("bob"));
        property.add(Item.READ, PermissionEntry.user("alice"));
        property.add(SCM.TAG, PermissionEntry.user("bob")); // use this to test for JENKINS-17200 robustness
        property.setInheritanceStrategy(new NonInheritingStrategy());
        SnippetizerTester tester = new SnippetizerTester(j);
        tester.assertRoundTrip(
                new JobPropertyStep(Collections.singletonList(property)),
                "properties([authorizationMatrix(inheritanceStrategy: nonInheriting(), "
                        + "permissions: ['USER:hudson.model.Item.Configure:alice', 'USER:hudson.model.Item.Read:alice', 'USER:hudson.model.Item.Read:bob', 'USER:hudson.scm.SCM.Tag:bob'])])");
    }

    @Test
    @Issue("JENKINS-46944")
    public void testSnippetizerInapplicablePermission() throws Exception {
        AuthorizationMatrixProperty property =
                new AuthorizationMatrixProperty(Collections.emptyMap(), new InheritParentStrategy());
        l.record(AuthorizationContainer.class, Level.WARNING).capture(3);
        property.add("hudson.model.Item.Configure:alice");
        property.add("hudson.model.Item.Read:bob");
        property.add("hudson.model.Item.Read:alice");
        property.add("hudson.scm.SCM.Tag:bob"); // use this to test for JENKINS-17200 robustness
        property.add("hudson.model.Hudson.Read:carol"); // the important line for this test, inapplicable permission
        property.add(
                "hudson.model.Hudson.Administer:dave"); // the important line for this test, inapplicable permission

        property.setInheritanceStrategy(new NonInheritingStrategy());

        SnippetizerTester tester = new SnippetizerTester(j);
        tester.assertRoundTrip(
                new JobPropertyStep(Collections.singletonList(property)),
                "properties([authorizationMatrix(inheritanceStrategy: nonInheriting(), "
                        + "permissions: ['hudson.model.Item.Configure:alice', 'hudson.model.Item.Read:alice', 'hudson.model.Item.Read:bob', 'hudson.scm.SCM.Tag:bob'])])");

        Assert.assertTrue(l.getMessages().stream()
                .anyMatch(m -> m.contains("Tried to add inapplicable permission")
                        && m.contains("Hudson,Read")
                        && m.contains("carol")));
        Assert.assertTrue(l.getMessages().stream()
                .anyMatch(m -> m.contains("Tried to add inapplicable permission")
                        && m.contains("Hudson,Administer")
                        && m.contains("dave")));
    }

    @Test
    public void testPipelineReconfiguration() throws Exception {

        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(true, false, null);
        realm.createAccount("alice", "alice");
        realm.createAccount("bob", "bob");
        realm.createAccount("carol", "carol");
        j.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy strategy = new ProjectMatrixAuthorizationStrategy();
        strategy.add(Jenkins.ADMINISTER, "alice");
        strategy.add(Jenkins.READ, "bob");
        strategy.add(Jenkins.READ, "carol");
        strategy.add(Item.READ, "carol");

        j.jenkins.setAuthorizationStrategy(strategy);

        WorkflowJob project = j.createProject(WorkflowJob.class);

        // bob cannot see the project due to lack of Item.Read
        j.createWebClient().login("bob").assertFails(project.getUrl(), 404);

        // but bob can discover the project and get a 403
        strategy.add(Item.DISCOVER, "bob");
        j.createWebClient().login("bob").assertFails(project.getUrl(), 403);

        // alice OTOH is admin and can see it
        j.createWebClient().login("alice").goTo(project.getUrl()); // succeeds

        // carol can also see the project, she has global Item.Read
        j.createWebClient().login("carol").goTo(project.getUrl());

        project.setDefinition(new CpsFlowDefinition(
                "properties([authorizationMatrix(inheritanceStrategy: nonInheriting(), "
                        + "permissions: ['hudson.model.Item.Read:bob', 'hudson.model.Item.Configure:bob', 'hudson.scm.SCM.Tag:bob'])])",
                true));
        j.buildAndAssertSuccess(project);

        // let's look ast the property
        AuthorizationMatrixProperty property = project.getProperty(AuthorizationMatrixProperty.class);
        Assert.assertTrue(property.getInheritanceStrategy() instanceof NonInheritingStrategy);
        Assert.assertEquals(3, property.getGrantedPermissions().size());
        Assert.assertEquals(3, property.getGrantedPermissionEntries().size());
        Assert.assertEquals("bob", property.getGroups().toArray()[0]);

        // now bob has access, including configure
        j.createWebClient().login("bob").goTo(project.getUrl());
        j.createWebClient().login("bob").goTo(project.getUrl() + "configure");

        // and carol no longer has access due to non-inheriting strategy
        j.createWebClient().login("carol").assertFails(project.getUrl(), 404);
    }

    @Test
    public void testPipelineReconfiguration2() throws Exception {

        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(true, false, null);
        realm.createAccount("alice", "alice");
        realm.createAccount("bob", "bob");
        realm.createAccount("carol", "carol");
        j.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy strategy = new ProjectMatrixAuthorizationStrategy();
        strategy.add(Jenkins.ADMINISTER, PermissionEntry.user("alice"));
        strategy.add(Jenkins.READ, PermissionEntry.user("bob"));
        strategy.add(Jenkins.READ, PermissionEntry.user("carol"));
        strategy.add(Item.READ, PermissionEntry.user("carol"));

        j.jenkins.setAuthorizationStrategy(strategy);

        WorkflowJob project = j.createProject(WorkflowJob.class);

        // bob cannot see the project due to lack of Item.Read
        j.createWebClient().login("bob").assertFails(project.getUrl(), 404);

        // but bob can discover the project and get a 403
        strategy.add(Item.DISCOVER, PermissionEntry.user("bob"));
        j.createWebClient().login("bob").assertFails(project.getUrl(), 403);

        // alice OTOH is admin and can see it
        j.createWebClient().login("alice").goTo(project.getUrl()); // succeeds

        // carol can also see the project, she has global Item.Read
        j.createWebClient().login("carol").goTo(project.getUrl());

        project.setDefinition(new CpsFlowDefinition(
                "properties([authorizationMatrix(inheritanceStrategy: nonInheriting(), "
                        + "permissions: ['USER:hudson.model.Item.Read:bob', 'USER:hudson.model.Item.Configure:bob', 'USER:hudson.scm.SCM.Tag:bob'])])",
                true));
        j.buildAndAssertSuccess(project);

        // let's look ast the property
        AuthorizationMatrixProperty property = project.getProperty(AuthorizationMatrixProperty.class);
        Assert.assertTrue(property.getInheritanceStrategy() instanceof NonInheritingStrategy);
        Assert.assertEquals(0, property.getGrantedPermissions().size()); // typed entries are not listed here
        Assert.assertEquals(3, property.getGrantedPermissionEntries().size());
        Assert.assertEquals(0, property.getGroups().size());

        // now bob has access, including configure
        j.createWebClient().login("bob").goTo(project.getUrl());
        j.createWebClient().login("bob").goTo(project.getUrl() + "configure");

        // and carol no longer has access due to non-inheriting strategy
        j.createWebClient().login("carol").assertFails(project.getUrl(), 404);
    }
}
