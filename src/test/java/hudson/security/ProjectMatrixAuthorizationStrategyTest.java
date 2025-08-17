package hudson.security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.*;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.User;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import jenkins.model.Jenkins;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlOption;
import org.htmlunit.html.HtmlSelect;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;
import org.springframework.security.core.Authentication;

@WithJenkins
class ProjectMatrixAuthorizationStrategyTest {

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
    }

    @Test
    void ensureCreatorHasPermissions() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false, false, null);
        realm.createAccount("alice", "alice");
        realm.createAccount("bob", "bob");
        j.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy authorizationStrategy = new ProjectMatrixAuthorizationStrategy();
        authorizationStrategy.add(Item.CREATE, "alice");
        authorizationStrategy.add(Jenkins.READ, "alice");
        authorizationStrategy.add(Jenkins.READ, "bob");
        j.jenkins.setAuthorizationStrategy(authorizationStrategy);

        Job<?, ?> job;
        try (ACLContext ignored = ACL.as(User.get("alice", false, Collections.emptyMap()))) {
            job = j.createFreeStyleProject();
        }

        assertNotNull(job.getProperty(AuthorizationMatrixProperty.class));
        assertTrue(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.READ));
        assertFalse(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("bob", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.READ));
        assertTrue(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.CONFIGURE));
    }

    @Test
    @Issue("JENKINS-58703")
    void ensureNoJobPropertyDuplication() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false, false, null);
        realm.createAccount("alice", "alice");
        realm.createAccount("bob", "bob");
        j.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy authorizationStrategy = new ProjectMatrixAuthorizationStrategy();
        authorizationStrategy.add(Item.CREATE, "alice");
        authorizationStrategy.add(Jenkins.READ, "alice");
        authorizationStrategy.add(Jenkins.READ, "bob");
        j.jenkins.setAuthorizationStrategy(authorizationStrategy);

        Job<?, ?> job;
        try (ACLContext ignored = ACL.as(User.get("alice", false, Collections.emptyMap()))) {
            j.jenkins.createProjectFromXML(
                    "job", getClass().getResourceAsStream(getClass().getSimpleName() + "/JENKINS-58703.xml"));
            job = j.jenkins.getItem("job", j.jenkins, Job.class);
        }

        assertNotNull(job.getProperty(AuthorizationMatrixProperty.class));
        assertTrue(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.READ));
        assertTrue(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("bob", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.READ));
        assertTrue(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.CONFIGURE));

        assertEquals(1, job.getAllProperties().size(), "one property");
    }

    @Test
    void submitEmptyPropertyEnsuresPermissionsForSubmitter() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false, false, null);
        realm.createAccount("alice", "alice");
        realm.createAccount("bob", "bob");
        j.jenkins.setSecurityRealm(realm);

        j.jenkins.setAuthorizationStrategy(new FullControlOnceLoggedInAuthorizationStrategy());

        // ensure logged in users are admins, but anon is not
        try (ACLContext ignored = ACL.as(User.get("alice", false, Collections.emptyMap()))) {
            assertTrue(j.jenkins.hasPermission(Jenkins.ADMINISTER), "alice is admin");
        }
        try (ACLContext ignored = ACL.as(User.get("bob", false, Collections.emptyMap()))) {
            assertTrue(j.jenkins.hasPermission(Jenkins.ADMINISTER), "bob is admin");
        }
        assertFalse(j.jenkins.getACL().hasPermission2(Jenkins.ANONYMOUS2, Jenkins.ADMINISTER), "anon is not admin");

        JenkinsRule.WebClient wc = j.createWebClient().login("alice");
        configureGlobalMatrixAuthStrategyThroughUI(wc);

        try (ACLContext ignored = ACL.as(User.get("alice", false, Collections.emptyMap()))) {
            // ensure that the user submitting the empty matrix will be admin
            assertTrue(j.jenkins.hasPermission(Jenkins.ADMINISTER), "alice is admin");
        }
        try (ACLContext ignored = ACL.as(User.get("bob", false, Collections.emptyMap()))) {
            assertFalse(j.jenkins.hasPermission(Jenkins.ADMINISTER), "bob is not admin");
        }
        assertFalse(j.jenkins.getACL().hasPermission2(Jenkins.ANONYMOUS2, Jenkins.ADMINISTER), "anon is not admin");
    }

    @Test
    void submitEmptyPropertyEnsuresPermissionsForAnonymousSubmitter() throws Exception {
        // prepare form to have options visible
        j.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(true, false, null));
        j.jenkins.setAuthorizationStrategy(new AuthorizationStrategy.Unsecured());

        assertTrue(j.jenkins.getACL().hasPermission2(Jenkins.ANONYMOUS2, Jenkins.ADMINISTER), "anon is admin");

        JenkinsRule.WebClient wc = j.createWebClient();
        configureGlobalMatrixAuthStrategyThroughUI(wc);

        assertTrue(j.jenkins.getACL().hasPermission2(Jenkins.ANONYMOUS2, Jenkins.ADMINISTER), "anon is admin");
        assertInstanceOf(GlobalMatrixAuthorizationStrategy.class, j.jenkins.getAuthorizationStrategy());
    }

    private void configureGlobalMatrixAuthStrategyThroughUI(JenkinsRule.WebClient wc) throws Exception {
        HtmlForm form = wc.goTo("configureSecurity").getFormByName("config");

        final Optional<HtmlElement> anyOption = form.getElementsByTagName("option").stream()
                .filter(option ->
                        option.getTextContent().contains(GlobalMatrixAuthorizationStrategy.DESCRIPTOR.getDisplayName()))
                .findAny();

        assertFalse(anyOption.isEmpty(), "expected to find an option");

        HtmlOption option = (HtmlOption) anyOption.get();
        HtmlSelect parent = (HtmlSelect) option.getParentNode();
        parent.setSelectedAttribute(option, true);
        j.submit(form);
    }

    @Test
    @LocalData
    void loadEmptyAuthorizationStrategy() {
        assertInstanceOf(HudsonPrivateSecurityRealm.class, j.jenkins.getSecurityRealm());
        assertInstanceOf(GlobalMatrixAuthorizationStrategy.class, j.jenkins.getAuthorizationStrategy());
    }

    @Test
    @LocalData
    void loadFilledAuthorizationStrategy() {
        assertInstanceOf(HudsonPrivateSecurityRealm.class, j.jenkins.getSecurityRealm());
        assertInstanceOf(ProjectMatrixAuthorizationStrategy.class, j.jenkins.getAuthorizationStrategy());

        ProjectMatrixAuthorizationStrategy authorizationStrategy =
                (ProjectMatrixAuthorizationStrategy) j.jenkins.getAuthorizationStrategy();
        assertTrue(authorizationStrategy.hasExplicitPermission("alice", Jenkins.ADMINISTER));
        assertFalse(authorizationStrategy.hasExplicitPermission("alice", Jenkins.READ));
        assertFalse(authorizationStrategy.hasExplicitPermission("bob", Jenkins.ADMINISTER));
    }

    @Test
    @Issue("JENKINS-39873")
    void subdirectoriesCanExcludeOtherNonAdminUsers() throws Exception {
        HudsonPrivateSecurityRealm securityRealm = new HudsonPrivateSecurityRealm(false, false, null);
        securityRealm.createAccount("admin", "admin");
        securityRealm.createAccount("alice", "alice");
        securityRealm.createAccount("bob", "bob");
        securityRealm.createAccount("carol", "carol");
        j.jenkins.setSecurityRealm(securityRealm);

        ProjectMatrixAuthorizationStrategy authorizationStrategy = new ProjectMatrixAuthorizationStrategy();
        authorizationStrategy.add(Jenkins.ADMINISTER, "admin");
        authorizationStrategy.add(Jenkins.READ, "alice");
        authorizationStrategy.add(Jenkins.READ, "bob");

        j.jenkins.setAuthorizationStrategy(authorizationStrategy);

        Folder f = j.jenkins.createProject(Folder.class, "Folder");

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

        ACL acl = j.jenkins.getAuthorizationStrategy().getACL(aliceProjects);

        Authentication alice = Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                .impersonate2();
        Authentication admin = Objects.requireNonNull(User.get("admin", false, Collections.emptyMap()))
                .impersonate2();
        Authentication bob = Objects.requireNonNull(User.get("bob", false, Collections.emptyMap()))
                .impersonate2();

        assertTrue(acl.hasPermission2(alice, Item.READ));
        assertTrue(acl.hasPermission2(alice, Item.CONFIGURE));
        assertTrue(acl.hasPermission2(admin, Item.READ));
        assertTrue(acl.hasPermission2(admin, Item.CONFIGURE));
        assertFalse(acl.hasPermission2(bob, Item.READ));
        assertFalse(acl.hasPermission2(bob, Item.CONFIGURE));

        JenkinsRule.WebClient wc = j.createWebClient().login("alice", "alice");
        wc.goTo(aliceProjects.getUrl());

        wc = j.createWebClient().login("admin", "admin");
        wc.goTo(aliceProjects.getUrl());

        assertThrows(
                FailingHttpStatusCodeException.class,
                () -> j.createWebClient().login("bob", "bob").goTo(aliceProjects.getUrl()));
    }

    @Test
    void getGroupsAlwaysEverything() throws IOException {
        HudsonPrivateSecurityRealm securityRealm = new HudsonPrivateSecurityRealm(false, false, null);
        j.jenkins.setSecurityRealm(securityRealm);

        ProjectMatrixAuthorizationStrategy authorizationStrategy = new ProjectMatrixAuthorizationStrategy();
        authorizationStrategy.add(Jenkins.READ, PermissionEntry.group("group1"));
        j.jenkins.setAuthorizationStrategy(authorizationStrategy);

        final Folder f = j.jenkins.createProject(Folder.class, "F");
        final FreeStyleProject job = f.createProject(FreeStyleProject.class, "job");
        job.addProperty(new AuthorizationMatrixProperty(
                Map.of(Item.READ, Set.of(PermissionEntry.group("group2"))), new InheritParentStrategy()));

        assertThat(authorizationStrategy.getGroups(), containsInAnyOrder("group1", "group2"));

        try (ACLContext ignored = ACL.as2(Jenkins.ANONYMOUS2)) {
            assertThat(authorizationStrategy.getGroups(), containsInAnyOrder("group1", "group2"));
        }
    }
}
