# matrix-auth-plugin
Matrix-based authorization strategies for Jenkins

Sample pipeline (assumes matrix based security enabled on jenkins):

    properties ([
  		  [$class: 'AuthorizationMatrixProperty',
    		    permissions : ['hudson.model.Item.Build:admin','hudson.model.Item.Build:user']
    		]
    ])
    
    node {
        stage 'ekho'
        sh 'echo bla'
    }


This will ensure admin and user have build permission on given project.

Other permissions:
* hudson.model.Item.Build
* hudson.model.Item.Cancel
* hudson.model.Item.Configure
* hudson.model.Item.Read
* hudson.model.Item.Workspace
* hudson.model.Run.Delete
* hudson.model.Run.Replay
* hudson.model.Run.Update
* hudson.model.Item.Read

Instead of named user, you can specify anonymous or other group.