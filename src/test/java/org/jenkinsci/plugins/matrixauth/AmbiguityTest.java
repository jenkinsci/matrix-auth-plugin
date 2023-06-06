package org.jenkinsci.plugins.matrixauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.hudson.plugins.folder.properties.FolderContributor;
import hudson.ExtensionList;
import hudson.model.Computer;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.Node;
import hudson.model.View;
import hudson.security.AuthorizationMatrixProperty;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import jenkins.model.Jenkins;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.html.HtmlFormUtil;
import org.htmlunit.html.HtmlPage;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.recipes.LocalData;

public class AmbiguityTest {
    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void anonymousIsUser() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        final GlobalMatrixAuthorizationStrategy userStrategy = new GlobalMatrixAuthorizationStrategy();
        userStrategy.add(Jenkins.READ, new PermissionEntry(AuthorizationType.USER, "anonymous"));
        j.jenkins.setAuthorizationStrategy(userStrategy);

        JenkinsRule.WebClient wc = j.createWebClient();
        wc.goTo(""); // no error

        // Legacy config still works
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        final GlobalMatrixAuthorizationStrategy eitherStrategy = new GlobalMatrixAuthorizationStrategy();
        eitherStrategy.add("hudson.model.Hudson.Read:anonymous");
        j.jenkins.setAuthorizationStrategy(eitherStrategy);

        wc.goTo(""); // no error
    }

    @Test
    public void anonymousIsAlsoGroup() throws Exception { // this wasn't always the case in older Jenkinses, but is now.
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        final GlobalMatrixAuthorizationStrategy groupStrategy = new GlobalMatrixAuthorizationStrategy();
        groupStrategy.add(Jenkins.READ, new PermissionEntry(AuthorizationType.GROUP, "anonymous"));
        j.jenkins.setAuthorizationStrategy(groupStrategy);

        JenkinsRule.WebClient wc = j.createWebClient();
        wc.goTo(""); // no error
    }

    @Test
    public void authenticatedIsAGroup() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        final GlobalMatrixAuthorizationStrategy userStrategy = new GlobalMatrixAuthorizationStrategy();
        userStrategy.add(Jenkins.READ, new PermissionEntry(AuthorizationType.GROUP, "authenticated"));
        j.jenkins.setAuthorizationStrategy(userStrategy);

        JenkinsRule.WebClient wc = j.createWebClient();
        wc.login("alice");
        wc.goTo(""); // no error

        final GlobalMatrixAuthorizationStrategy groupStrategy = new GlobalMatrixAuthorizationStrategy();
        groupStrategy.add(Jenkins.READ, new PermissionEntry(AuthorizationType.USER, "authenticated"));
        j.jenkins.setAuthorizationStrategy(groupStrategy);
        FailingHttpStatusCodeException ex = assertThrows(FailingHttpStatusCodeException.class, () -> wc.goTo(""));
        assertEquals("permission denied", 403, ex.getStatusCode());

        // Legacy config would still work
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        final GlobalMatrixAuthorizationStrategy eitherStrategy = new GlobalMatrixAuthorizationStrategy();
        eitherStrategy.add("hudson.model.Hudson.Read:authenticated");
        j.jenkins.setAuthorizationStrategy(eitherStrategy);

        wc.goTo(""); // no error
    }

    @Test
    public void usersAreUsers() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        final GlobalMatrixAuthorizationStrategy userStrategy = new GlobalMatrixAuthorizationStrategy();
        userStrategy.add(Jenkins.READ, new PermissionEntry(AuthorizationType.USER, "alice"));
        j.jenkins.setAuthorizationStrategy(userStrategy);

        JenkinsRule.WebClient wc = j.createWebClient();
        wc.login("alice");
        wc.goTo(""); // no error

        final GlobalMatrixAuthorizationStrategy groupStrategy = new GlobalMatrixAuthorizationStrategy();
        groupStrategy.add(Jenkins.READ, new PermissionEntry(AuthorizationType.GROUP, "alice"));
        j.jenkins.setAuthorizationStrategy(groupStrategy);
        FailingHttpStatusCodeException ex = assertThrows(FailingHttpStatusCodeException.class, () -> wc.goTo(""));
        assertEquals("permission denied", 403, ex.getStatusCode());

        // Legacy config would still work
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        final GlobalMatrixAuthorizationStrategy eitherStrategy = new GlobalMatrixAuthorizationStrategy();
        eitherStrategy.add("hudson.model.Hudson.Read:alice");
        j.jenkins.setAuthorizationStrategy(eitherStrategy);

        wc.goTo(""); // no error
    }

    @Test
    public void adminMonitorAppearsAndDisappears() throws Exception {
        assertAdminMonitorVisible(false);
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        final GlobalMatrixAuthorizationStrategy userStrategy = new GlobalMatrixAuthorizationStrategy();
        j.jenkins.setAuthorizationStrategy(userStrategy);
        assertAdminMonitorVisible(false);

        userStrategy.add(Jenkins.READ, PermissionEntry.group("authenticated"));
        assertAdminMonitorVisible(false);

        userStrategy.add(Jenkins.READ, "authenticated");
        assertAdminMonitorVisible(true);

        j.jenkins.setAuthorizationStrategy(new GlobalMatrixAuthorizationStrategy());
        assertAdminMonitorVisible(false);

        final FreeStyleProject project = j.createFreeStyleProject();
        project.addProperty(new AuthorizationMatrixProperty(
                Collections.singletonMap(Item.READ, Collections.singleton(PermissionEntry.group("authenticated"))),
                new InheritParentStrategy()));
        assertAdminMonitorVisible(false);

        final FreeStyleProject project2 = j.createFreeStyleProject();
        project2.addProperty(new AuthorizationMatrixProperty(
                Collections.singletonMap(Item.READ, Collections.singleton("authenticated"))));
        project2.save();
        assertAdminMonitorVisible(false); // wrong strategy: global, not project based!

        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy());
        assertAdminMonitorVisible(false);

        j.jenkins.setAuthorizationStrategy(new ProjectMatrixAuthorizationStrategy());
        assertAdminMonitorVisible(true);

        project2.delete(); // tests ItemListenerImpl#onDeleted
        assertAdminMonitorVisible(false);

        project.removeProperty(AuthorizationMatrixProperty.class);
        assertAdminMonitorVisible(false); // unchanged

        project.addProperty(new AuthorizationMatrixProperty(
                Collections.singletonMap(Item.READ, Collections.singleton("authenticated"))));
        assertAdminMonitorVisible(true);
        project.save();
        assertAdminMonitorVisible(true);

        project.removeProperty(AuthorizationMatrixProperty.class);
        assertAdminMonitorVisible(false);
    }

    @LocalData
    @Test
    public void testDataFrom2xReconfiguration() throws Exception {
        assertAdminMonitorVisible(true);
        AmbiguityMonitor ambiguityMonitor =
                (AmbiguityMonitor) j.jenkins.getAdministrativeMonitor(AmbiguityMonitor.class.getName());
        assertNotNull(ambiguityMonitor);

        ExtensionList<AmbiguityMonitor.Contributor> contributors =
                j.jenkins.getExtensionList(AmbiguityMonitor.Contributor.class);
        AmbiguityMonitor.GlobalConfigurationContributor globalConfigurationContributor =
                contributors.get(AmbiguityMonitor.GlobalConfigurationContributor.class);
        AmbiguityMonitor.JobContributor jobContributor = contributors.get(AmbiguityMonitor.JobContributor.class);
        AmbiguityMonitor.NodeContributor nodeContributor = contributors.get(AmbiguityMonitor.NodeContributor.class);
        FolderContributor folderContributor = contributors.get(FolderContributor.class);

        assertNotNull(globalConfigurationContributor);
        assertTrue(globalConfigurationContributor.hasAmbiguousEntries());

        { // admin monitor entries are as expected
            assertNotNull(folderContributor);
            assertTrue(folderContributor.activeFolders.get("F"));
            assertNotNull(jobContributor);
            assertTrue(jobContributor.activeJobs.get("F/fs"));
            assertNotNull(nodeContributor);
            assertTrue(nodeContributor.activeNodes.get("a1"));
        }

        JenkinsRule.WebClient wc = j.createWebClient().login("admin");

        { // migrate all ambiguous entries to user
            final HtmlPage agentPage = wc.goTo("computer/a1/configure");
            agentPage.executeJavaScript(
                    "Array.from(document.querySelectorAll('.migrate_user')).forEach(el => el.click());");
            HtmlFormUtil.submit(agentPage.getFormByName("config"));
        }

        assertFalse(nodeContributor.activeNodes.get("a1"));

        { // ensure permissions were migrated as expected on the node
            // object changes on submission, so need to get a new one
            final Node node = j.jenkins.getNode("a1");
            assertNotNull(node);
            final AuthorizationMatrixNodeProperty nodeProperty =
                    node.getNodeProperty(AuthorizationMatrixNodeProperty.class);
            assertNotNull(nodeProperty);
            assertTrue(nodeProperty.hasExplicitPermission(PermissionEntry.user("anonymous"), Computer.BUILD));
            assertFalse(nodeProperty.hasExplicitPermission(PermissionEntry.group("anonymous"), Computer.BUILD));
            assertFalse(nodeProperty.hasExplicitPermission(
                    new PermissionEntry(AuthorizationType.EITHER, "anonymous"), Computer.CONFIGURE));

            // we migrated everything to "user", which is weird for 'authenticated' but whatever
            assertTrue(nodeProperty.hasExplicitPermission(PermissionEntry.user("authenticated"), Computer.CONFIGURE));
            assertTrue(nodeProperty.hasExplicitPermission(PermissionEntry.user("authenticated"), Computer.CONNECT));
            assertTrue(nodeProperty.hasExplicitPermission(PermissionEntry.user("authenticated"), Computer.DISCONNECT));
            assertFalse(nodeProperty.hasExplicitPermission(PermissionEntry.group("authenticated"), Computer.CONFIGURE));
            assertFalse(nodeProperty.hasExplicitPermission(PermissionEntry.group("authenticated"), Computer.CONNECT));
            assertFalse(
                    nodeProperty.hasExplicitPermission(PermissionEntry.group("authenticated"), Computer.DISCONNECT));
            assertFalse(nodeProperty.hasExplicitPermission(
                    new PermissionEntry(AuthorizationType.EITHER, "authenticated"), Computer.CONFIGURE));
            assertFalse(nodeProperty.hasExplicitPermission(
                    new PermissionEntry(AuthorizationType.EITHER, "authenticated"), Computer.CONNECT));
            assertFalse(nodeProperty.hasExplicitPermission(
                    new PermissionEntry(AuthorizationType.EITHER, "authenticated"), Computer.DISCONNECT));
        }

        { // assert loaded permissions on the folder
            final Folder f = (Folder) j.jenkins.getItemByFullName("F");
            assertNotNull(f);
            assertTrue(
                    folderContributor.activeFolders.get("F")); // presented by the Redundancy Department of Redundancy

            final com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty folderProperty =
                    f.getProperties()
                            .get(com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty.class);
            assertNotNull(folderProperty);
            for (Permission permission : Arrays.asList(View.CONFIGURE, View.CREATE, View.DELETE, View.READ)) {
                // legacy authenticated has all 4 permissions, nobody else has any
                assertFalse(folderProperty.hasExplicitPermission(PermissionEntry.group("authenticated"), permission));
                assertFalse(folderProperty.hasExplicitPermission(PermissionEntry.user("authenticated"), permission));
                assertTrue(folderProperty.hasExplicitPermission(
                        new PermissionEntry(AuthorizationType.EITHER, "authenticated"), permission));
                assertFalse(folderProperty.hasExplicitPermission(PermissionEntry.group("anonymous"), permission));
                assertFalse(folderProperty.hasExplicitPermission(PermissionEntry.user("anonymous"), permission));
                assertFalse(folderProperty.hasExplicitPermission(
                        new PermissionEntry(AuthorizationType.EITHER, "anonymous"), permission));
            }
        }

        { // migrate all ambiguous entries to group
            final HtmlPage agentPage = wc.goTo("job/F/configure");
            agentPage.executeJavaScript(
                    "Array.from(document.querySelectorAll('.migrate_group')).forEach(el => el.click());");
            HtmlFormUtil.submit(agentPage.getFormByName("config"));
        }

        { // ensure permissions were migrated as expected on the folder
            assertFalse(folderContributor.activeFolders.get("F"));

            final Folder f = (Folder) j.jenkins.getItemByFullName("F");
            assertNotNull(f);
            final com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty folderProperty =
                    f.getProperties()
                            .get(com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty.class);
            assertNotNull(folderProperty);
            for (Permission permission : Arrays.asList(View.CONFIGURE, View.CREATE, View.DELETE, View.READ)) {
                // authenticated group has all 4 permissions, nobody else has any
                assertTrue(folderProperty.hasExplicitPermission(PermissionEntry.group("authenticated"), permission));
                assertFalse(folderProperty.hasExplicitPermission(PermissionEntry.user("authenticated"), permission));
                assertFalse(folderProperty.hasExplicitPermission(
                        new PermissionEntry(AuthorizationType.EITHER, "authenticated"), permission));
                assertFalse(folderProperty.hasExplicitPermission(PermissionEntry.group("anonymous"), permission));
                assertFalse(folderProperty.hasExplicitPermission(PermissionEntry.user("anonymous"), permission));
                assertFalse(folderProperty.hasExplicitPermission(
                        new PermissionEntry(AuthorizationType.EITHER, "anonymous"), permission));
            }
        }

        // TODO assert job too or are the above enough?
    }

    @LocalData
    @Test
    public void testDataFrom2xDeletion() throws Exception {
        assertAdminMonitorVisible(true);
        AmbiguityMonitor ambiguityMonitor =
                (AmbiguityMonitor) j.jenkins.getAdministrativeMonitor(AmbiguityMonitor.class.getName());
        assertNotNull(ambiguityMonitor);

        AmbiguityMonitor.GlobalConfigurationContributor globalConfigurationContributor =
                ExtensionList.lookupSingleton(AmbiguityMonitor.GlobalConfigurationContributor.class);
        AmbiguityMonitor.JobContributor jobContributor =
                ExtensionList.lookupSingleton(AmbiguityMonitor.JobContributor.class);
        AmbiguityMonitor.NodeContributor nodeContributor =
                ExtensionList.lookupSingleton(AmbiguityMonitor.NodeContributor.class);
        FolderContributor folderContributor = ExtensionList.lookupSingleton(FolderContributor.class);

        assertFalse(globalConfigurationContributor.hasAmbiguousEntries()); // "previously migrated"

        assertTrue(jobContributor.activeJobs.get("F/fs"));
        final Item job = j.jenkins.getItemByFullName("F/fs");
        assertNotNull(job);
        job.delete();
        assertEquals(0, jobContributor.activeJobs.size());

        assertTrue(folderContributor.activeFolders.get("F"));
        final Item folder = j.jenkins.getItemByFullName("F");
        assertNotNull(folder);
        folder.delete();
        assertEquals(0, folderContributor.activeFolders.size());

        assertTrue(nodeContributor.activeNodes.get("a1"));
        j.jenkins.removeNode(Objects.requireNonNull(j.jenkins.getNode("a1")));
        assertEquals(0, nodeContributor.activeNodes.size());
    }

    private void assertAdminMonitorVisible(boolean visible) {
        assertEquals(
                "admin monitor should be visible? ",
                visible,
                Objects.requireNonNull(j.jenkins.getAdministrativeMonitor(AmbiguityMonitor.class.getName()))
                        .isActivated());
    }
}
