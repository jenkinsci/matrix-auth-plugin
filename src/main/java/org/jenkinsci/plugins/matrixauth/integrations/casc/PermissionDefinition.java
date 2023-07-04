package org.jenkinsci.plugins.matrixauth.integrations.casc;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import hudson.security.Permission;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainer;
import org.jenkinsci.plugins.matrixauth.integrations.PermissionFinder;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Wrapper for {@link hudson.security.Permission} referenced in JCasC
 */
public class PermissionDefinition {
    private Permission permission;

    @DataBoundConstructor
    public PermissionDefinition(String permission) {
        this.permission = PermissionFinder.findPermission(permission);
    }

    private PermissionDefinition(Permission permission) {
        this.permission = permission;
    }

    public Permission getPermission() {
        return permission;
    }

    public static PermissionDefinition forPermission(Permission permission) {
        return new PermissionDefinition(permission);
    }

    public static class ConverterImpl implements Converter {
        @Override
        public void marshal(Object o, HierarchicalStreamWriter reader, MarshallingContext marshallingContext) {
            PermissionDefinition p = (PermissionDefinition) o;
            reader.setValue(p.permission.group.title + "/" + p.permission.name);
        }

        @Override
        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext unmarshallingContext) {
            String value = reader.getValue();
            return PermissionDefinition.forPermission(AuthorizationContainer.parsePermission(value));
        }

        @Override
        public boolean canConvert(Class type) {
            return type == PermissionDefinition.class;
        }
    }
}
