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

import hudson.model.Descriptor;
import hudson.security.Permission;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategy;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerRequest;

/**
 * Interface with default methods common to all authorization related property descriptors.
 *
 */
@Restricted(NoExternalUse.class)
public interface AuthorizationPropertyDescriptor<T extends AuthorizationProperty>
        extends AuthorizationContainerDescriptor {

    Logger LOGGER = Logger.getLogger(AuthorizationPropertyDescriptor.class.getName());

    T create();

    default T createNewInstance(StaplerRequest req, JSONObject formData, boolean hasOptionalWrap)
            throws Descriptor.FormException {
        if (hasOptionalWrap) {
            formData = formData.getJSONObject("useProjectSecurity");
            if (formData.isNullObject()) return null;
        }

        T property = create();

        Map<String, Object> data = formData.getJSONObject("data");

        property.setInheritanceStrategy(
                req.bindJSON(InheritanceStrategy.class, formData.getJSONObject("inheritanceStrategy")));

        for (Map.Entry<String, Object> r : data.entrySet()) {
            String permissionEntryString = r.getKey();
            PermissionEntry entry = PermissionEntry.fromString(permissionEntryString);
            if (entry == null) {
                LOGGER.log(Level.FINE, () -> "Failed to parse PermissionEntry from string: " + permissionEntryString);
                continue;
            }

            if (!(r.getValue() instanceof JSONObject)) {
                throw new Descriptor.FormException("not an object: " + formData, "data");
            }
            Map<String, Object> value = (JSONObject) r.getValue();

            for (Map.Entry<String, Object> e : value.entrySet()) {
                if (!(e.getValue() instanceof Boolean)) {
                    throw new Descriptor.FormException("not an boolean: " + formData, "data");
                }
                if ((Boolean) e.getValue()) {
                    Permission p = Permission.fromId(e.getKey());
                    if (p == null) {
                        LOGGER.log(
                                Level.FINE,
                                "Silently skip unknown permission \"{0}\" for sid:\"{1}\", type: {2}",
                                new Object[] {e.getKey(), entry.getSid(), entry.getType()});
                    } else {
                        property.add(p, entry);
                    }
                }
            }
        }
        return property;
    }

    default boolean isApplicable() {
        // only applicable when ProjectMatrixAuthorizationStrategy is in charge
        return Jenkins.get().getAuthorizationStrategy() instanceof ProjectMatrixAuthorizationStrategy;
    }
}
