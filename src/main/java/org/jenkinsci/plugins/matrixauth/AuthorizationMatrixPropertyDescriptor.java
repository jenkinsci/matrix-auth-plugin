/*
 * The MIT License
 *
 * Copyright (c) 2004-2017, Sun Microsystems, Inc., Kohsuke Kawaguchi, Yahoo! Inc., Peter Hayes, Tom Huybrechts, Daniel Beck
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.matrixauth;

import hudson.security.Permission;
import hudson.security.PermissionGroup;
import hudson.security.PermissionScope;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface AuthorizationMatrixPropertyDescriptor<T extends AuthorizationProperty> {

    T createProperty();

    PermissionScope getPermissionScope();

    default T createNewInstance(StaplerRequest req, JSONObject formData, boolean hasOptionalWrap) {
        if (hasOptionalWrap) {
            formData = formData.getJSONObject("useProjectSecurity");
            if (formData.isNullObject())
                return null;
        }

        T amnp = createProperty();

        // Disable inheritance, if so configured
        amnp.setBlocksInheritance(!formData.getJSONObject("blocksInheritance").isNullObject());

        for (Map.Entry<String, Object> r : (Set<Map.Entry<String, Object>>) formData.getJSONObject("data").entrySet()) {
            String sid = r.getKey();
            if (r.getValue() instanceof JSONObject) {
                for (Map.Entry<String, Boolean> e : (Set<Map.Entry<String, Boolean>>) ((JSONObject) r
                        .getValue()).entrySet()) {
                    if (e.getValue()) {
                        Permission p = Permission.fromId(e.getKey());
                        amnp.add(p, sid);
                    }
                }
            }
        }
        return amnp;
    }

    default boolean isApplicable() {
        // only applicable when ProjectMatrixAuthorizationStrategy is in charge
        try {
            return Jenkins.getInstance().getAuthorizationStrategy() instanceof ProjectMatrixAuthorizationStrategy;
        } catch (NoClassDefFoundError x) { // after matrix-auth split?
            return false;
        }
    }

    @Nonnull
    default String getDisplayName() {
        return "Authorization Matrix"; // TODO i18n
    }

    default List<PermissionGroup> getAllGroups() {
        List<PermissionGroup> groups = new ArrayList<>();
        for (PermissionGroup g : PermissionGroup.getAll()) {
            if (g.hasPermissionContainedBy(getPermissionScope())) {
                groups.add(g);
            }
        }
        return groups;
    }

    default boolean showPermission(Permission p) {
        return p.getEnabled() && p.isContainedBy(getPermissionScope());
    }
}
