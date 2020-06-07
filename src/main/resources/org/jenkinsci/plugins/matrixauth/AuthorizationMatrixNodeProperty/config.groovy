package org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty

import lib.FormTagLib
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategyDescriptor

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")

f.nested {
    blockWrapper {
        f.dropdownDescriptorSelector(title: _("Inheritance Strategy"), descriptors: InheritanceStrategyDescriptor.getApplicableDescriptors(my?.class?:hudson.model.Node.class), field: 'inheritanceStrategy')
        st.include(class: "hudson.security.GlobalMatrixAuthorizationStrategy", page: "config")
    }
    
}

// TODO remove this once https://github.com/jenkinsci/jenkins/pull/3895 is in the core baseline
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
