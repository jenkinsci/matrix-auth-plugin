package hudson.security;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import hudson.util.RobustReflectionConverter;

import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class AbstractMatrixPropertyConverter implements Converter {
    abstract public boolean canConvert(Class type);

    abstract public AuthorizationProperty createSubject();

    public void marshal(Object source, HierarchicalStreamWriter writer,
                        MarshallingContext context) {
        AuthorizationProperty authorizationProperty = (AuthorizationProperty) source;

        if (authorizationProperty.isBlocksInheritance()) {
            writer.startNode("blocksInheritance");
            writer.setValue("true");
            writer.endNode();
        }

        for (Map.Entry<Permission, Set<String>> e : authorizationProperty.getGrantedPermissions()
                .entrySet()) {
            String p = e.getKey().getId();
            for (String sid : e.getValue()) {
                writer.startNode("permission");
                writer.setValue(p + ':' + sid);
                writer.endNode();
            }
        }
    }

    public Object unmarshal(HierarchicalStreamReader reader,
                            final UnmarshallingContext context) {
        AuthorizationProperty authorizationProperty = createSubject();

        String prop = reader.peekNextChild();

        if (prop!=null && prop.equals("useProjectSecurity")) {
            reader.moveDown();
            reader.getValue(); // we used to use this but not any more.
            reader.moveUp();
            prop = reader.peekNextChild(); // We check the next field
        }
        if ("blocksInheritance".equals(prop)) {
            reader.moveDown();
            authorizationProperty.setBlocksInheritance("true".equals(reader.getValue()));
            reader.moveUp();
        }

        while (reader.hasMoreChildren()) {
            reader.moveDown();
            try {
                authorizationProperty.add(reader.getValue());
            } catch (IllegalArgumentException ex) {
                Logger.getLogger(AuthorizationMatrixProperty.class.getName())
                        .log(Level.WARNING,"Skipping a non-existent permission",ex);
                RobustReflectionConverter.addErrorInContext(context, ex);
            }
            reader.moveUp();
        }

        return authorizationProperty;
    }
}
