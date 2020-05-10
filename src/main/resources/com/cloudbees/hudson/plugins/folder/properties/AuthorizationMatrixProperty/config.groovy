package com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty

import lib.FormTagLib
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategyDescriptor

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")

f.optionalBlock(name: 'useProjectSecurity', checked: instance != null, title: _("Enable project-based security")) {
    f.nested {
        blockWrapper {
            f.dropdownDescriptorSelector(title: _("Inheritance Strategy"), descriptors: InheritanceStrategyDescriptor.getApplicableDescriptors(my.class), field: 'inheritanceStrategy')
            st.include(class: "hudson.security.GlobalMatrixAuthorizationStrategy", page: "config")
        }
    }
}

def blockWrapper(Closure closure) {
    if (context.getVariableWithDefaultValue("divBasedFormLayout", "false") == "true") {
        div() {
            closure.call()
        }
    } else {
        table(style: "width: 100%") {
            closure.call()
        }
    }
}
