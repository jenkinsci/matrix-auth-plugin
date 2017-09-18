package hudson.security;

import hudson.model.Item;
import hudson.scm.SCM;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.cps.SnippetizerTester;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.multibranch.JobPropertyStep;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.Collections;

public class AuthorizationMatrixPropertyTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void testSnippetizer() throws Exception {
        AuthorizationMatrixProperty property = new AuthorizationMatrixProperty(Collections.emptyMap());
        property.add(Item.CONFIGURE, "alice");
        property.add(Item.READ, "bob");
        property.add(Item.READ, "alice");
        property.add(SCM.TAG, "bob"); // use this to test for JENKINS-17200 robustness
        property.setInheritanceStrategy(new NonInheritingStrategy());
        SnippetizerTester tester = new SnippetizerTester(j);
        tester.assertRoundTrip(new JobPropertyStep(Collections.singletonList(property)),
                "properties([authorizationMatrix(inheritanceStrategy: nonInheriting(), " +
                "permissions: ['hudson.model.Item.Configure:alice', 'hudson.model.Item.Read:alice', 'hudson.model.Item.Read:bob', 'hudson.scm.SCM.Tag:bob'])])");
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

        project.setDefinition(new CpsFlowDefinition("properties([authorizationMatrix(inheritanceStrategy: nonInheriting(), " +
                "permissions: ['hudson.model.Item.Read:bob', 'hudson.model.Item.Configure:bob', 'hudson.scm.SCM.Tag:bob'])])", true));
        j.buildAndAssertSuccess(project);

        // let's look ast the property
        AuthorizationMatrixProperty property = project.getProperty(AuthorizationMatrixProperty.class);
        Assert.assertTrue(property.getInheritanceStrategy() instanceof NonInheritingStrategy);
        Assert.assertEquals(3, property.getGrantedPermissions().size());
        Assert.assertEquals("bob", property.getGroups().toArray()[0]);

        // now bob has access, including configure
        j.createWebClient().login("bob").goTo(project.getUrl());
        j.createWebClient().login("bob").goTo(project.getUrl() + "configure");

        // and carol no longer has access due to non-inheriting strategy
        j.createWebClient().login("carol").assertFails(project.getUrl(), 404);
    }
}
