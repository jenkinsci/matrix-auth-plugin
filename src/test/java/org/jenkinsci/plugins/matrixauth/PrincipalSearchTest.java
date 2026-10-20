package org.jenkinsci.plugins.matrixauth;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import com.cloudbees.hudson.plugins.folder.Folder;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.Computer;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import hudson.security.SecurityRealm;
import hudson.slaves.DumbSlave;
import io.jenkins.plugins.authcommons.Principal;
import io.jenkins.plugins.authcommons.PrincipalSearchProvider;
import io.jenkins.plugins.authcommons.PrincipalType;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.htmlunit.Page;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class PrincipalSearchTest {

    private JenkinsRule j;
    private JenkinsRule.DummySecurityRealm realm;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
        realm = j.createDummySecurityRealm();
        j.jenkins.setSecurityRealm(realm);
    }

    @Test
    void searchPermissions() throws Exception {
        FreeStyleProject project = j.createFreeStyleProject("p");
        Folder folder = j.jenkins.createProject(Folder.class, "f");
        DumbSlave agent = j.createSlave("agent", null, null);

        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin")
                .grant(Jenkins.READ)
                .everywhere()
                .to("configurer", "reader")
                .grant(Item.READ, Item.CONFIGURE)
                .onItems(project, folder)
                .to("configurer")
                .grant(Computer.CONFIGURE)
                .everywhere()
                .to("configurer")
                .grant(Item.READ)
                .onItems(project, folder)
                .to("reader"));

        String global =
                "descriptorByName/" + GlobalMatrixAuthorizationStrategy.class.getName() + "/searchPrincipals?q=al";
        String job = "job/p/descriptorByName/" + hudson.security.AuthorizationMatrixProperty.class.getName()
                + "/searchPrincipals?q=al";
        String folderUrl = "job/f/descriptorByName/"
                + com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty.class.getName()
                + "/searchPrincipals?q=al&type=GROUP";
        String node = "computer/" + agent.getNodeName() + "/descriptorByName/"
                + AuthorizationMatrixNodeProperty.class.getName() + "/searchPrincipals?q=al&type=USER";

        assertResults("admin", global, "USER:alice", "USER:albert", "GROUP:alpha");
        assertResults("admin", job, "USER:alice", "USER:albert", "GROUP:alpha");
        assertResults("admin", folderUrl, "GROUP:alpha");
        assertResults("admin", node, "USER:alice", "USER:albert");

        assertStatus("configurer", global, 403);
        assertResults("configurer", job, "USER:alice", "USER:albert", "GROUP:alpha");
        assertResults("configurer", folderUrl, "GROUP:alpha");
        assertResults("configurer", node, "USER:alice", "USER:albert");

        assertStatus("reader", global, 403);
        assertStatus("reader", job, 403);
        assertStatus("reader", folderUrl, 403);
        assertStatus("reader", node, 403);
    }

    @Test
    void configPageOffersAutocompletion() throws Exception {
        ProjectMatrixAuthorizationStrategy strategy = new ProjectMatrixAuthorizationStrategy();
        strategy.add(Jenkins.ADMINISTER, PermissionEntry.user("admin"));
        j.jenkins.setAuthorizationStrategy(strategy);

        try (JenkinsRule.WebClient wc = j.createWebClient().login("admin")) {
            String content =
                    wc.goTo("manage/configureSecurity").getWebResponse().getContentAsString();
            assertThat(content, containsString("mas-principal-search-template"));
            assertThat(content, containsString("auth-commons-principal-search"));
            assertThat(
                    content,
                    containsString("data-search-url=\"/jenkins/manage/descriptorByName/"
                            + ProjectMatrixAuthorizationStrategy.class.getName() + "/searchPrincipals\""));
        }

        HudsonPrivateSecurityRealm privateRealm = new HudsonPrivateSecurityRealm(false, false, null);
        privateRealm.createAccount("admin", "correct-horse-battery-staple");
        j.jenkins.setSecurityRealm(privateRealm);
        try (JenkinsRule.WebClient wc = j.createWebClient().login("admin", "correct-horse-battery-staple")) {
            String content =
                    wc.goTo("manage/configureSecurity").getWebResponse().getContentAsString();
            assertThat(content, containsString("matrix-auth-add-button"));
            assertThat(content, not(containsString("mas-principal-search-template")));
            assertThat(content, not(containsString("searchPrincipals")));
        }
    }

    @Test
    void displayNameFromProvider() {
        realm.addGroups("alice", "alpha");
        GlobalMatrixAuthorizationStrategy.DescriptorImpl descriptor = (GlobalMatrixAuthorizationStrategy.DescriptorImpl)
                j.jenkins.getDescriptorOrDie(GlobalMatrixAuthorizationStrategy.class);

        assertThat(descriptor.doCheckName("[USER:alice]").renderHtml(), containsString("Alice Liddell"));
        assertThat(descriptor.doCheckName("[GROUP:alpha]").renderHtml(), containsString("Alpha Team"));
        // unknown to the provider, so the realm's name is used
        assertThat(descriptor.doCheckName("[USER:bob]").renderHtml(), containsString(">bob<"));
    }

    @Test
    void directoryKnowsSidsTheRealmCannotResolve() {
        // e.g. directory users who never logged in
        j.jenkins.setSecurityRealm(new DirectoryOnlyRealm());
        GlobalMatrixAuthorizationStrategy.DescriptorImpl descriptor = (GlobalMatrixAuthorizationStrategy.DescriptorImpl)
                j.jenkins.getDescriptorOrDie(GlobalMatrixAuthorizationStrategy.class);

        String alice = descriptor.doCheckName("[USER:alice]").renderHtml();
        assertThat(alice, containsString("Alice Liddell"));
        assertThat(alice, not(containsString("not-found")));
        String alpha = descriptor.doCheckName("[GROUP:alpha]").renderHtml();
        assertThat(alpha, containsString("Alpha Team"));
        assertThat(alpha, not(containsString("not-found")));
        // unknown to both
        assertThat(descriptor.doCheckName("[USER:bob]").renderHtml(), containsString("not-found"));
    }

    /** A realm that resolves nobody, leaving it to the search provider. */
    public static class DirectoryOnlyRealm extends HudsonPrivateSecurityRealm {
        DirectoryOnlyRealm() {
            super(false, false, null);
        }
    }

    private void assertResults(String user, String url, String... expected) throws Exception {
        try (JenkinsRule.WebClient wc = j.createWebClient().login(user)) {
            Page page = wc.goTo(url, "application/json");
            JSONArray results = JSONObject.fromObject(page.getWebResponse().getContentAsString())
                    .getJSONArray("results");
            List<String> actual = new ArrayList<>();
            for (int i = 0; i < results.size(); i++) {
                JSONObject result = results.getJSONObject(i);
                actual.add(result.getString("type") + ":" + result.getString("sid"));
            }
            assertThat(user + " " + url, actual, is(List.of(expected)));
        }
    }

    private void assertStatus(String user, String url, int status) throws Exception {
        try (JenkinsRule.WebClient wc = j.createWebClient().login(user)) {
            wc.setThrowExceptionOnFailingStatusCode(false);
            Page page = wc.goTo(url, null);
            assertThat(user + " " + url, page.getWebResponse().getStatusCode(), is(status));
        }
    }

    @TestExtension
    public static class TestProvider extends PrincipalSearchProvider {
        private static final List<Principal> DIRECTORY = List.of(
                Principal.user("alice", "Alice Liddell", "alice@example.com"),
                Principal.user("albert", "Albert", null),
                Principal.group("alpha", "Alpha Team", null));

        @Override
        public boolean isApplicable(@NonNull SecurityRealm realm) {
            return realm instanceof JenkinsRule.DummySecurityRealm || realm instanceof DirectoryOnlyRealm;
        }

        @NonNull
        @Override
        public List<Principal> search(@NonNull String query, @NonNull Set<PrincipalType> types, int limit) {
            return DIRECTORY.stream()
                    .filter(p -> p.sid().startsWith(query) && types.contains(p.type()))
                    .toList();
        }

        @Override
        public Principal lookup(@NonNull String sid, @NonNull PrincipalType type) {
            return DIRECTORY.stream()
                    .filter(p -> p.sid().equals(sid) && p.type() == type)
                    .findFirst()
                    .orElse(null);
        }
    }
}
