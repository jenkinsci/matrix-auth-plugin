package org.jenkinsci.plugins.matrixauth;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import hudson.model.User;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.util.FormValidation;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@WithJenkins
public class ValidationUtilTest {

    // Needed for Symbol lookups
    private static JenkinsRule j;

    @BeforeAll
    static void setUp(JenkinsRule rule) {
        j = rule;
    }

    @Test
    void testBasicUserValidation() {
        final DummySecurityRealmWithGroupDisplayNames securityRealm = new DummySecurityRealmWithGroupDisplayNames();
        FormValidation fv;
        {
            // basic user name
            fv = ValidationUtil.validateUser("foo", securityRealm, false);
            assertNotNull(fv);
            assertThat(fv.kind, is(FormValidation.Kind.OK));
            assertThat(fv.renderHtml(), containsString("</svg>foo</div>"));
            assertThat(fv.renderHtml(), containsString("<div tooltip='User' class='mas-table__cell'>"));
        }
        {
            // Ambiguous basic user name
            fv = ValidationUtil.validateUser("foo", securityRealm, true);
            assertNotNull(fv);
            assertThat(fv.kind, is(FormValidation.Kind.WARNING));
            assertThat(fv.renderHtml(), containsString("</svg>foo</div>"));
            assertThat(
                    fv.renderHtml(),
                    containsString(
                            "<div tooltip='User found; but permissions would also be granted to a group of this name' class='mas-table__cell mas-table__cell-warning'>"));
        }
        User.get("foo").setFullName("Mr Foo");
        {
            // User with full name
            fv = ValidationUtil.validateUser("foo", securityRealm, false);
            assertNotNull(fv);
            assertThat(fv.kind, is(FormValidation.Kind.OK));
            assertThat(fv.renderHtml(), containsString("</svg>Mr Foo</div>"));
            assertThat(fv.renderHtml(), containsString("<div tooltip='User foo' class='mas-table__cell'>"));
        }
        {
            // Ambiguous user with full name
            fv = ValidationUtil.validateUser("foo", securityRealm, true);
            assertNotNull(fv);
            assertThat(fv.kind, is(FormValidation.Kind.WARNING));
            assertThat(fv.renderHtml(), containsString("</svg>Mr Foo</div>"));
            assertThat(
                    fv.renderHtml(),
                    containsString(
                            "<div tooltip='User foo found; but permissions would also be granted to a group of this name' class='mas-table__cell mas-table__cell-warning'>"));
        }
    }

    @Test
    void testBasicGroupValidation() {
        final DummySecurityRealmWithGroupDisplayNames securityRealm = new DummySecurityRealmWithGroupDisplayNames();
        FormValidation fv;
        {
            // group not found
            fv = ValidationUtil.validateGroup("foo", securityRealm, false);
            assertNull(fv);
        }
        securityRealm.addGroups("alice", "foo");
        {
            // basic group name
            fv = ValidationUtil.validateGroup("foo", securityRealm, false);
            assertNotNull(fv);
            assertThat(fv.kind, is(FormValidation.Kind.OK));
            assertThat(fv.renderHtml(), containsString("</svg>foo</div>"));
            assertThat(fv.renderHtml(), containsString("<div tooltip='Group' class='mas-table__cell'>"));
        }
        {
            // ambiguous basic group name
            fv = ValidationUtil.validateGroup("foo", securityRealm, true);
            assertNotNull(fv);
            assertThat(fv.kind, is(FormValidation.Kind.WARNING));
            assertThat(fv.renderHtml(), containsString("</svg>foo</div>"));
            assertThat(
                    fv.renderHtml(),
                    containsString(
                            "<div tooltip='Group found; but permissions would also be granted to a user of this name' class='mas-table__cell mas-table__cell-warning'>"));
        }
        securityRealm.groupDisplayNames.put("foo", "Foo Group");
        {
            //  group with display name
            fv = ValidationUtil.validateGroup("foo", securityRealm, false);
            assertNotNull(fv);
            assertThat(fv.kind, is(FormValidation.Kind.OK));
            assertThat(fv.renderHtml(), containsString("</svg>Foo Group</div>"));
            assertThat(fv.renderHtml(), containsString("<div tooltip='Group foo' class='mas-table__cell'>"));
        }
        {
            //  Ambiguous group with display name
            fv = ValidationUtil.validateGroup("foo", securityRealm, true);
            assertNotNull(fv);
            assertThat(fv.kind, is(FormValidation.Kind.WARNING));
            assertThat(fv.renderHtml(), containsString("</svg>Foo Group</div>"));
            assertThat(
                    fv.renderHtml(),
                    containsString(
                            "<div tooltip='Group foo found; but permissions would also be granted to a user of this name' class='mas-table__cell mas-table__cell-warning'>"));
        }
    }

    // Largely copied from jenkins-test-harness as its constructor is package-private
    private static class DummySecurityRealmWithGroupDisplayNames extends AbstractPasswordBasedSecurityRealm {
        private final Map<String, Set<String>> groupsByUser = new HashMap();

        private final Map<String, String> groupDisplayNames = new HashMap();

        protected UserDetails authenticate2(String username, String password) throws AuthenticationException {
            if (username.equals(password)) {
                return this.loadUserByUsername2(username);
            } else {
                throw new BadCredentialsException(username);
            }
        }

        public UserDetails loadUserByUsername2(String username) throws UsernameNotFoundException {
            List<GrantedAuthority> auths = new ArrayList();
            auths.add(AUTHENTICATED_AUTHORITY2);
            Set<String> groups = (Set) this.groupsByUser.get(username);
            if (groups != null) {
                for (String g : groups) {
                    auths.add(new SimpleGrantedAuthority(g));
                }
            }

            return new org.springframework.security.core.userdetails.User(username, "", true, true, true, true, auths);
        }

        public GroupDetails loadGroupByGroupname(final String groupname) throws UsernameNotFoundException {
            for (Set<String> groups : this.groupsByUser.values()) {
                if (groups.contains(groupname)) {
                    return new GroupDetails() {
                        public String getName() {
                            return groupname;
                        }

                        public String getDisplayName() {
                            return groupDisplayNames.getOrDefault(groupname, groupname);
                        }
                    };
                }
            }

            throw new UsernameNotFoundException(groupname);
        }

        public void addGroups(String username, String... groups) {
            Set<String> gs = (Set) this.groupsByUser.computeIfAbsent(username, (k) -> new TreeSet());
            gs.addAll(List.of(groups));
        }
    }
}
