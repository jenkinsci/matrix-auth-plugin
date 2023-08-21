package org.jenkinsci.plugins.matrixauth.integrations.casc;

import hudson.security.Permission;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.commons.beanutils.Converter;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainer;

/**
 * Wrapper for {@link hudson.security.Permission} referenced in JCasC
 */
public class PermissionDefinition {
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
        return permission.group.title + "/" + permission.name;
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
                                .map(p -> p.permission.group.title + "/" + p.permission.name)
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
