package hudson.security;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.User;
import hudson.util.VersionNumber;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;
import jenkins.model.Jenkins;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlOption;
import org.htmlunit.html.HtmlSelect;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;
import org.springframework.security.core.Authentication;

public class ProjectMatrixAuthorizationStrategyTest {

    @Rule
    public JenkinsRule r = new JenkinsRule();

    @Test
    public void ensureCreatorHasPermissions() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false, false, null);
        realm.createAccount("alice", "alice");
        realm.createAccount("bob", "bob");
        r.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy authorizationStrategy = new ProjectMatrixAuthorizationStrategy();
        authorizationStrategy.add(Item.CREATE, "alice");
        authorizationStrategy.add(Jenkins.READ, "alice");
        authorizationStrategy.add(Jenkins.READ, "bob");
        r.jenkins.setAuthorizationStrategy(authorizationStrategy);

        Job<?, ?> job;
        try (ACLContext ignored = ACL.as(User.get("alice", false, Collections.emptyMap()))) {
            job = r.createFreeStyleProject();
        }

        Assert.assertNotNull(job.getProperty(AuthorizationMatrixProperty.class));
        Assert.assertTrue(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.READ));
        Assert.assertFalse(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("bob", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.READ));
        Assert.assertTrue(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.CONFIGURE));
    }

    @Test
    @Issue("JENKINS-58703")
    public void ensureNoJobPropertyDuplication() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false, false, null);
        realm.createAccount("alice", "alice");
        realm.createAccount("bob", "bob");
        r.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy authorizationStrategy = new ProjectMatrixAuthorizationStrategy();
        authorizationStrategy.add(Item.CREATE, "alice");
        authorizationStrategy.add(Jenkins.READ, "alice");
        authorizationStrategy.add(Jenkins.READ, "bob");
        r.jenkins.setAuthorizationStrategy(authorizationStrategy);

        Job<?, ?> job;
        try (ACLContext ignored = ACL.as(User.get("alice", false, Collections.emptyMap()))) {
            r.jenkins.createProjectFromXML(
                    "job", getClass().getResourceAsStream(getClass().getSimpleName() + "/JENKINS-58703.xml"));
            job = r.jenkins.getItem("job", r.jenkins, Job.class);
        }

        Assert.assertNotNull(job.getProperty(AuthorizationMatrixProperty.class));
        Assert.assertTrue(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.READ));
        Assert.assertTrue(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("bob", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.READ));
        Assert.assertTrue(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.CONFIGURE));

        Assert.assertEquals("one property", 1, job.getAllProperties().size());
    }

    @Test
    public void submitEmptyPropertyEnsuresPermissionsForSubmitter() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false, false, null);
        realm.createAccount("alice", "alice");
        realm.createAccount("bob", "bob");
        r.jenkins.setSecurityRealm(realm);

        r.jenkins.setAuthorizationStrategy(new FullControlOnceLoggedInAuthorizationStrategy());

        // ensure logged in users are admins, but anon is not
        try (ACLContext ignored = ACL.as(User.get("alice", false, Collections.emptyMap()))) {
            Assert.assertTrue("alice is admin", r.jenkins.hasPermission(Jenkins.ADMINISTER));
        }
        try (ACLContext ignored = ACL.as(User.get("bob", false, Collections.emptyMap()))) {
            Assert.assertTrue("bob is admin", r.jenkins.hasPermission(Jenkins.ADMINISTER));
        }
        Assert.assertFalse(
                "anon is not admin", r.jenkins.getACL().hasPermission2(Jenkins.ANONYMOUS2, Jenkins.ADMINISTER));

        JenkinsRule.WebClient wc = r.createWebClient().login("alice");
        configureGlobalMatrixAuthStrategyThroughUI(wc);

        try (ACLContext ignored = ACL.as(User.get("alice", false, Collections.emptyMap()))) {
            // ensure that the user submitting the empty matrix will be admin
            Assert.assertTrue("alice is admin", r.jenkins.hasPermission(Jenkins.ADMINISTER));
        }
        try (ACLContext ignored = ACL.as(User.get("bob", false, Collections.emptyMap()))) {
            Assert.assertFalse("bob is not admin", r.jenkins.hasPermission(Jenkins.ADMINISTER));
        }
        Assert.assertFalse(
                "anon is not admin", r.jenkins.getACL().hasPermission2(Jenkins.ANONYMOUS2, Jenkins.ADMINISTER));
    }

    @Test
    public void submitEmptyPropertyEnsuresPermissionsForAnonymousSubmitter() throws Exception {
        // prepare form to have options visible
        r.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(true, false, null));
        r.jenkins.setAuthorizationStrategy(new AuthorizationStrategy.Unsecured());

        Assert.assertTrue("anon is admin", r.jenkins.getACL().hasPermission2(Jenkins.ANONYMOUS2, Jenkins.ADMINISTER));

        JenkinsRule.WebClient wc = r.createWebClient();
        configureGlobalMatrixAuthStrategyThroughUI(wc);

        Assert.assertTrue("anon is admin", r.jenkins.getACL().hasPermission2(Jenkins.ANONYMOUS2, Jenkins.ADMINISTER));
        Assert.assertTrue(r.jenkins.getAuthorizationStrategy() instanceof GlobalMatrixAuthorizationStrategy);
    }

    private void configureGlobalMatrixAuthStrategyThroughUI(JenkinsRule.WebClient wc) throws Exception {
        HtmlForm form = wc.goTo("configureSecurity").getFormByName("config");

        if (new VersionNumber("2.342").isOlderThanOrEqualTo(Jenkins.getVersion())) {
            final Optional<HtmlElement> anyOption = form.getElementsByTagName("option").stream()
                    .filter(option -> option.getTextContent()
                            .contains(GlobalMatrixAuthorizationStrategy.DESCRIPTOR.getDisplayName()))
                    .findAny();

            if (!anyOption.isPresent()) {
                throw new IllegalStateException("expected to find an option");
            }
            HtmlOption option = (HtmlOption) anyOption.get();
            HtmlSelect parent = (HtmlSelect) option.getParentNode();
            parent.setSelectedAttribute(option, true);
        } else {
            Optional<HtmlElement> anyLabel = form.getElementsByTagName("label").stream()
                    .filter(lbl -> lbl.asNormalizedText()
                            .contains(GlobalMatrixAuthorizationStrategy.DESCRIPTOR.getDisplayName()))
                    .findAny();
            if (!anyLabel.isPresent()) {
                throw new IllegalStateException("expected to find a label");
            }
            HtmlElement label = anyLabel.get();
            label.click();
        }
        r.submit(form);
    }

    @Test
    @LocalData
    public void loadEmptyAuthorizationStrategy() {
        Assert.assertTrue(r.jenkins.getSecurityRealm() instanceof HudsonPrivateSecurityRealm);
        Assert.assertTrue(r.jenkins.getAuthorizationStrategy() instanceof GlobalMatrixAuthorizationStrategy);
    }

    @Test
    @LocalData
    public void loadFilledAuthorizationStrategy() {
        Assert.assertTrue(r.jenkins.getSecurityRealm() instanceof HudsonPrivateSecurityRealm);
        Assert.assertTrue(r.jenkins.getAuthorizationStrategy() instanceof ProjectMatrixAuthorizationStrategy);

        ProjectMatrixAuthorizationStrategy authorizationStrategy =
                (ProjectMatrixAuthorizationStrategy) r.jenkins.getAuthorizationStrategy();
        Assert.assertTrue(authorizationStrategy.hasExplicitPermission("alice", Jenkins.ADMINISTER));
        Assert.assertFalse(authorizationStrategy.hasExplicitPermission("alice", Jenkins.READ));
        Assert.assertFalse(authorizationStrategy.hasExplicitPermission("bob", Jenkins.ADMINISTER));
    }

    @Test
    @Issue("JENKINS-39873")
    public void subdirectoriesCanExcludeOtherNonAdminUsers() throws Exception {
        HudsonPrivateSecurityRealm securityRealm = new HudsonPrivateSecurityRealm(false, false, null);
        securityRealm.createAccount("admin", "admin");
        securityRealm.createAccount("alice", "alice");
        securityRealm.createAccount("bob", "bob");
        securityRealm.createAccount("carol", "carol");
        r.jenkins.setSecurityRealm(securityRealm);

        ProjectMatrixAuthorizationStrategy authorizationStrategy = new ProjectMatrixAuthorizationStrategy();
        authorizationStrategy.add(Jenkins.ADMINISTER, "admin");
        authorizationStrategy.add(Jenkins.READ, "alice");
        authorizationStrategy.add(Jenkins.READ, "bob");

        r.jenkins.setAuthorizationStrategy(authorizationStrategy);

        Folder f = r.jenkins.createProject(Folder.class, "Folder");

        com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty amp =
                new com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty(Collections.emptyMap());

        amp.add(Item.READ, "alice");
        amp.add(Item.READ, "bob");
        f.getProperties().add(amp);

        Folder aliceProjects = f.createProject(Folder.class, "alice");

        com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty aliceProp =
                new com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty(Collections.emptyMap());
        aliceProp.setInheritanceStrategy(new NonInheritingStrategy());
        aliceProp.add(Item.READ, "alice");
        aliceProp.add(Item.CONFIGURE, "alice");

        aliceProjects.getProperties().add(aliceProp);

        ACL acl = r.jenkins.getAuthorizationStrategy().getACL(aliceProjects);

        Authentication alice = Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                .impersonate2();
        Authentication admin = Objects.requireNonNull(User.get("admin", false, Collections.emptyMap()))
                .impersonate2();
        Authentication bob = Objects.requireNonNull(User.get("bob", false, Collections.emptyMap()))
                .impersonate2();

        Assert.assertTrue(acl.hasPermission2(alice, Item.READ));
        Assert.assertTrue(acl.hasPermission2(alice, Item.CONFIGURE));
        Assert.assertTrue(acl.hasPermission2(admin, Item.READ));
        Assert.assertTrue(acl.hasPermission2(admin, Item.CONFIGURE));
        Assert.assertFalse(acl.hasPermission2(bob, Item.READ));
        Assert.assertFalse(acl.hasPermission2(bob, Item.CONFIGURE));

        JenkinsRule.WebClient wc = r.createWebClient().login("alice", "alice");
        wc.goTo(aliceProjects.getUrl());

        wc = r.createWebClient().login("admin", "admin");
        wc.goTo(aliceProjects.getUrl());

        wc = r.createWebClient().login("bob", "bob");
        try {
            wc.goTo(aliceProjects.getUrl());
            Assert.fail();
        } catch (Exception expected) {
            // expected
        }
    }
}
