package hudson.security;

import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlLabel;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.User;
import jenkins.model.Jenkins;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class ProjectMatrixAuthorizationStrategyTest {

    @Rule
    public JenkinsRule r = new JenkinsRule();

    @Test
    public void ensureCreatorHasPermissions() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false);
        realm.createAccount("alice","alice");
        realm.createAccount("bob","bob");
        r.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy authorizationStrategy = new ProjectMatrixAuthorizationStrategy();
        authorizationStrategy.add(Item.CREATE, "alice");
        authorizationStrategy.add(Jenkins.READ, "alice");
        authorizationStrategy.add(Jenkins.READ, "bob");
        r.jenkins.setAuthorizationStrategy(authorizationStrategy);
        
        Job job;
        try (ACLContext _ = ACL.as(User.get("alice"))) {
            job = r.createFreeStyleProject();
        }

        Assert.assertNotNull(job.getProperty(AuthorizationMatrixProperty.class));
        Assert.assertTrue(job.getACL().hasPermission(User.get("alice").impersonate(), Item.READ));
        Assert.assertFalse(job.getACL().hasPermission(User.get("bob").impersonate(), Item.READ));
        Assert.assertTrue(job.getACL().hasPermission(User.get("alice").impersonate(), Item.CONFIGURE));
    }

    @Test
    public void submitEmptyPropertyEnsuresPermissionsForSubmitter() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false);
        realm.createAccount("alice","alice");
        realm.createAccount("bob","bob");
        r.jenkins.setSecurityRealm(realm);

        r.jenkins.setAuthorizationStrategy(new FullControlOnceLoggedInAuthorizationStrategy());

        // ensure logged in users are admins, but anon is not
        try (ACLContext _ = ACL.as(User.get("alice"))) {
            Assert.assertTrue("alice is admin", r.jenkins.hasPermission(Jenkins.ADMINISTER));
        }
        try (ACLContext _ = ACL.as(User.get("bob"))) {
            Assert.assertTrue("bob is admin", r.jenkins.hasPermission(Jenkins.ADMINISTER));
        }
        Assert.assertFalse("anon is not admin", r.jenkins.getACL().hasPermission(Jenkins.ANONYMOUS, Jenkins.ADMINISTER));

        JenkinsRule.WebClient wc = r.createWebClient().login("alice");
        HtmlForm form = wc.goTo("configureSecurity").getFormByName("config");

        // TODO this must be possible in a nicer way
        HtmlElement label = form.getElementsByTagName("label").stream().filter(
                lbl -> lbl.asText().contains(GlobalMatrixAuthorizationStrategy.DESCRIPTOR.getDisplayName())).findAny().get();
        ((HtmlLabel)label).click();
        r.submit(form);

        try (ACLContext _ = ACL.as(User.get("alice"))) {
            // ensure that the user submitting the empty matrix will be admin
            Assert.assertTrue("alice is admin", r.jenkins.hasPermission(Jenkins.ADMINISTER));
        }
        try (ACLContext _ = ACL.as(User.get("bob"))) {
            Assert.assertFalse("bob is not admin", r.jenkins.hasPermission(Jenkins.ADMINISTER));
        }
        Assert.assertFalse("anon is not admin", r.jenkins.getACL().hasPermission(Jenkins.ANONYMOUS, Jenkins.ADMINISTER));
    }

    @Test
    public void submitEmptyPropertyEnsuresPermissionsForAnonymousSubmitter() throws Exception {
        // prepare form to have options visible
        r.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(true));
        r.jenkins.setAuthorizationStrategy(new AuthorizationStrategy.Unsecured());

        Assert.assertTrue("anon is admin", r.jenkins.getACL().hasPermission(Jenkins.ANONYMOUS, Jenkins.ADMINISTER));

        JenkinsRule.WebClient wc = r.createWebClient();
        HtmlForm form = wc.goTo("configureSecurity").getFormByName("config");

        // TODO this must be possible in a nicer way
        HtmlElement label = form.getElementsByTagName("label").stream().filter(
                lbl -> lbl.asText().contains(GlobalMatrixAuthorizationStrategy.DESCRIPTOR.getDisplayName())).findAny().get();
        ((HtmlLabel)label).click();
        r.submit(form);

        Assert.assertTrue("anon is admin", r.jenkins.getACL().hasPermission(Jenkins.ANONYMOUS, Jenkins.ADMINISTER));
        Assert.assertTrue(r.jenkins.getAuthorizationStrategy() instanceof GlobalMatrixAuthorizationStrategy);
    }
}
