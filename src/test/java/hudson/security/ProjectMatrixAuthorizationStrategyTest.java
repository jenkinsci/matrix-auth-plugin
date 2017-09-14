package hudson.security;

import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlLabel;
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
        HtmlElement label = form.getElementsByTagName("label").stream().filter(lbl -> lbl.asText().contains("Matrix-based security")).findAny().get();
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
        HtmlElement label = form.getElementsByTagName("label").stream().filter(lbl -> lbl.asText().contains("Matrix-based security")).findAny().get();
        ((HtmlLabel)label).click();
        r.submit(form);

        Assert.assertTrue("anon is admin", r.jenkins.getACL().hasPermission(Jenkins.ANONYMOUS, Jenkins.ADMINISTER));
        Assert.assertTrue(r.jenkins.getAuthorizationStrategy() instanceof GlobalMatrixAuthorizationStrategy);
    }
}
