# Background

Devolutions Gateway uses token to communicate with provisioner. The token is a JWT signed by the provisioner.


## Task Token type
Task token is used for provisioner to assign a task to the Gateway actively. 
We keep task tokens extendable, one task token carries payload specific to that task.

Task token is consumed on receive.