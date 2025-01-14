/*
 * The MIT License
 *
 * Copyright (c) 2023 Daniel Beck
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
package org.jenkinsci.plugins.matrixauth.integrations.casc;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.security.Permission;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.commons.beanutils.Converter;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainer;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Wrapper for {@link hudson.security.Permission} referenced in JCasC
 */
@Restricted(NoExternalUse.class)
public class PermissionDefinition implements Comparable<PermissionDefinition> {
    private Permission permission;

    private PermissionDefinition(Permission permission) {
        this.permission = permission;
    }

    public Permission getPermission() {
        return permission;
    }

    public static PermissionDefinition forPermission(Permission permission) {
        return new PermissionDefinition(permission);
    }

    @Override
    public String toString() {
        return permission.group.getId() + "/" + permission.name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PermissionDefinition that = (PermissionDefinition) o;
        return Objects.equals(permission.toString(), that.permission.toString());
    }

    @Override
    public int hashCode() {
        return Objects.hash(permission.toString());
    }

    @Override
    public int compareTo(@NonNull PermissionDefinition o) {
        return this.toString().compareTo(o.toString());
    }

    public static class StaplerConverterImpl implements Converter {
        @Override
        public Object convert(Class target, Object o) {
            if (o == null) {
                return null;
            }

            if (target == PermissionDefinition.class && o instanceof List) {
                // JCasC export provides an ArrayList<PermissionDefinition> and requests a PermissionDefinition !?
                return ((List<?>) o)
                        .stream()
                                .map(p -> (PermissionDefinition) p)
                                .map(p -> p.permission.group.getId() + "/" + p.permission.name)
                                .collect(Collectors.toList());
            }

            if (target == PermissionDefinition.class && o instanceof String) {
                // import provides a String and asks for a PermissionDefinition
                return PermissionDefinition.forPermission(AuthorizationContainer.parsePermission((String) o));
            }

            throw new IllegalArgumentException("Failed to convert '" + o + "' to " + target);
        }
    }
}
